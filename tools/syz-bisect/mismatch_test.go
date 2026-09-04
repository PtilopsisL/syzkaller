// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestCloneRuntimeConfigEnablesSnapshot(t *testing.T) {
	src := &mgrconfig.Config{
		Snapshot:          false,
		Workdir:           "/source/work",
		KernelSrc:         "/source/kernel",
		KernelBuildSrc:    "/source/build",
		KernelObj:         "/source/obj",
		PrimaryRuntime:    "primary",
		ComparisonPrimary: "comparison",
	}
	clone := cloneRuntimeConfig(src, "/bisect/work", "/bisect/kernel")
	if !clone.Snapshot {
		t.Fatal("mismatch runtime must enable snapshot mode")
	}
	if src.Snapshot {
		t.Fatal("cloneRuntimeConfig modified the source config")
	}
	if clone.Workdir != "/bisect/work" || clone.KernelSrc != "/bisect/kernel" {
		t.Fatalf("clone did not use private paths: %+v", clone)
	}
}

func TestWaitMismatchResultsReportsRuntimeExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expected := errors.New("test runtime failure")
	loopDone := make(chan error, 1)
	loopDone <- expected

	_, observed, err := waitMismatchResults(ctx, []*queue.Request{{}}, loopDone)
	if !observed {
		t.Fatal("runtime exit was not observed")
	}
	if !errors.Is(err, expected) {
		t.Fatalf("waitMismatchResults error = %v, want %v", err, expected)
	}
}

func TestWaitMismatchResultsPreservesRequestOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := []*queue.Request{{}, {}}
	requests[0].Done(&queue.Result{Status: queue.Success})
	requests[1].Done(&queue.Result{Status: queue.Crashed})

	results, observed, err := waitMismatchResults(ctx, requests, make(chan error))
	if err != nil {
		t.Fatal(err)
	}
	if observed {
		t.Fatal("runtime should not have been observed as exited")
	}
	if len(results) != len(requests) || results[0].Status != queue.Success ||
		results[1].Status != queue.Crashed {
		t.Fatalf("request result order was not preserved: %+v", results)
	}
}

func TestClassifyMismatchPoints(t *testing.T) {
	keyA, keyB := "a", "b"
	history, err := classifyMismatchPoints([]mismatchRuntimePoint{
		{Name: "old-1", Key: keyA},
		{Name: "old-2", Key: keyA},
		{Name: "new-1", Key: keyB},
		{Name: "new-2", Key: keyB},
	})
	if err != nil {
		t.Fatal(err)
	}
	if history.Pattern != "AABB" || history.Good.Name != "old-2" || history.Bad.Name != "new-2" {
		t.Fatalf("unexpected history: pattern=%q good=%q bad=%q",
			history.Pattern, history.Good.Name, history.Bad.Name)
	}
	for _, points := range [][]mismatchRuntimePoint{
		{{Name: "a", Key: keyA}, {Name: "b", Key: keyB}, {Name: "c", Key: keyA}},
		{{Name: "a", Key: keyA}, {Name: "b", Key: keyB}, {Name: "c", Key: "c"}},
		{{Name: "a", Key: keyA}},
	} {
		if _, err := classifyMismatchPoints(points); err == nil {
			t.Fatalf("expected non-monotonic history to be rejected: %+v", points)
		}
	}
}

func TestMismatchBehaviorKeyCanonicalizesValues(t *testing.T) {
	report := &storedMismatchForBisect{
		StableDifferences: []storedMismatchDifference{
			{Kind: "return_value", Path: "calls[0].return_value", Values: map[string]json.RawMessage{
				"old": json.RawMessage(`{"resource":"fd"}`),
				"new": json.RawMessage(`{"resource":"fd2"}`),
			}},
			{Kind: "status", Path: "status", Values: map[string]json.RawMessage{
				"old": json.RawMessage(`0`), "new": json.RawMessage(`2`),
			}},
		},
	}
	old, err := mismatchBehaviorKey((*storedMismatchForBisect)(report), "old")
	if err != nil {
		t.Fatal(err)
	}
	// The map order in Values must not influence the digest. Reversing the
	// stable-difference order also must not change it.
	report.StableDifferences[0], report.StableDifferences[1] =
		report.StableDifferences[1], report.StableDifferences[0]
	oldAgain, err := mismatchBehaviorKey(report, "old")
	if err != nil {
		t.Fatal(err)
	}
	if old != oldAgain {
		t.Fatalf("behavior key changed after reordering fields: %q != %q", old, oldAgain)
	}
}

func TestCanonicalJSONPreservesIntegers(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{"9007199254740993", "9007199254740993"},
		{"9223372036854775807", "9223372036854775807"},
		{"-9223372036854775808", "-9223372036854775808"},
		{"18446744073709551615", "18446744073709551615"},
		{` {"z": [18446744073709551615, -9223372036854775808], "a": 9007199254740993} `,
			`{"a":9007199254740993,"z":[18446744073709551615,-9223372036854775808]}`},
		{" null ", "null"},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, err := canonicalJSON(json.RawMessage(test.input))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("canonicalJSON = %s, want %s", got, test.want)
			}
		})
	}
	for _, input := range []string{"", " ", "{", "1 2", "1 true", "1 trailing"} {
		if _, err := canonicalJSON(json.RawMessage(input)); err == nil {
			t.Fatalf("invalid JSON %q was accepted", input)
		}
	}
}

func TestMismatchBehaviorKeyPreservesIntegers(t *testing.T) {
	p := &prog.Prog{Calls: []*prog.Call{{Meta: &prog.Syscall{}}}}
	for _, values := range [][2]int64{
		{9007199254740992, 9007199254740993},
		{-9007199254740992, -9007199254740993},
		{9223372036854775806, 9223372036854775807},
		{-9223372036854775808, -9223372036854775807},
	} {
		report := &storedMismatchForBisect{
			StableDifferences: []storedMismatchDifference{{
				Kind: "return_value", Path: "calls[0].return_value",
				Values: map[string]json.RawMessage{
					"old": json.RawMessage(fmt.Sprint(values[0])),
					"new": json.RawMessage(fmt.Sprint(values[1])),
				},
			}},
		}
		var keys []string
		for index, name := range []string{"old", "new"} {
			key, err := mismatchBehaviorKey(report, name)
			if err != nil {
				t.Fatal(err)
			}
			result := &queue.Result{Status: queue.Success, Info: &flatrpc.ProgInfo{
				Calls: []*flatrpc.CallInfo{{
					Flags:            flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
					ReturnValue:      values[index],
					ReturnValueValid: true,
				}},
			}}
			candidateKey, err := candidateBehaviorKey(report, p, result)
			if err != nil {
				t.Fatal(err)
			}
			if candidateKey != key {
				t.Fatalf("candidate return value %d does not match its report", values[index])
			}
			keys = append(keys, key)
		}
		if keys[0] == keys[1] {
			t.Fatalf("distinct return values %v have identical behavior keys", values)
		}
	}
}

func TestScanMinimizedMismatches(t *testing.T) {
	workdir := t.TempDir()
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report := `{"format_version":4,"parent_prog_id":12,"outcome":"mismatch","runtimes":["old","new"],"stable_differences":[{"kind":"status","path":"status","values":{"old":0,"new":2}}]}`
	write(filepath.Join(workdir, "runtime-mismatches", "prog12", "minimize", "report.json"), report)
	write(filepath.Join(workdir, "runtime-mismatches", "prog12", "minimize", "repro.prog"), "getpid()\n")
	// A completed marker excludes a program even when its report is otherwise
	// valid.
	write(filepath.Join(workdir, "runtime-mismatches", "prog13", "cause.commit"), "deadbeef\n")
	write(filepath.Join(workdir, "runtime-mismatches", "prog13", "minimize", "report.json"), report)
	write(filepath.Join(workdir, "runtime-mismatches", "prog13", "minimize", "repro.prog"), "getpid()\n")
	// Incomplete report directories are ignored and retried on a later run.
	write(filepath.Join(workdir, "runtime-mismatches", "prog14", "minimize", "report.json"), report)

	candidates, err := scanMinimizedMismatches(workdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].ProgID != 12 {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}

func TestLoadSingleMismatchCandidatePaths(t *testing.T) {
	workdir := t.TempDir()
	root := filepath.Join(workdir, "runtime-mismatches", "prog21")
	minimize := filepath.Join(root, "minimize")
	report := `{"format_version":4,"parent_prog_id":21,"outcome":"mismatch","runtimes":["old","new"],"stable_differences":[{"kind":"status","path":"status","values":{"old":0,"new":2}}]}`
	os.MkdirAll(minimize, 0o755)
	os.WriteFile(filepath.Join(minimize, "report.json"), []byte(report), 0o644)
	os.WriteFile(filepath.Join(minimize, "repro.prog"), []byte("getpid()\n"), 0o644)

	for _, path := range []string{root, minimize, filepath.Join(minimize, "report.json")} {
		candidate, err := loadSingleMismatchCandidate(path)
		if err != nil {
			t.Fatalf("load %q: %v", path, err)
		}
		if candidate.ProgID != 21 || candidate.Dir != root || candidate.ReproPath != filepath.Join(minimize, "repro.prog") {
			t.Fatalf("unexpected candidate for %q: %+v", path, candidate)
		}
	}
	if !looksLikeMismatchPath(filepath.Join(workdir, "runtime-mismatches")) ||
		!looksLikeMismatchPath(root) || !looksLikeMismatchPath(minimize) ||
		!looksLikeMismatchPath(filepath.Join(minimize, "report.json")) {
		t.Fatal("mismatch paths were not recognized")
	}
	crashDir := filepath.Join(workdir, "crashes", "old-crash")
	os.MkdirAll(crashDir, 0o755)
	os.WriteFile(filepath.Join(crashDir, "repro.prog"), []byte("getpid()\n"), 0o644)
	if looksLikeMismatchPath(crashDir) {
		t.Fatal("ordinary crash directory was recognized as a mismatch")
	}

	os.WriteFile(filepath.Join(root, mismatchCauseFile), []byte("deadbeef\n"), 0o644)
	if _, err := loadSingleMismatchCandidate(minimize); err == nil {
		t.Fatal("expected an already-bisected report to be rejected")
	}
}

func TestLoadMismatchCandidatesBatch(t *testing.T) {
	workdir := t.TempDir()
	base := filepath.Join(workdir, "runtime-mismatches")
	writeCandidate := func(id int, completed bool) {
		t.Helper()
		dir := filepath.Join(base, fmt.Sprintf("prog%d", id))
		minimize := filepath.Join(dir, "minimize")
		if err := os.MkdirAll(minimize, 0o755); err != nil {
			t.Fatal(err)
		}
		report := fmt.Sprintf(`{"format_version":4,"parent_prog_id":%d,"outcome":"mismatch","runtimes":["old","new"],"stable_differences":[{"kind":"status","path":"status","values":{"old":0,"new":2}}]}`, id)
		if err := os.WriteFile(filepath.Join(minimize, "report.json"), []byte(report), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(minimize, "repro.prog"), []byte("getpid()\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if completed {
			if err := os.WriteFile(filepath.Join(dir, mismatchCauseFile), []byte("deadbeef\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeCandidate(31, false)
	writeCandidate(29, false)
	writeCandidate(30, true)
	brokenDir := filepath.Join(base, "prog32", "minimize")
	if err := os.MkdirAll(brokenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "report.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "repro.prog"), []byte("getpid()\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	selection, err := loadMismatchCandidates(base)
	if err != nil {
		t.Fatal(err)
	}
	if !selection.Batch {
		t.Fatal("runtime-mismatches directory was not recognized as a batch")
	}
	if len(selection.Candidates) != 2 || selection.Candidates[0].ProgID != 29 ||
		selection.Candidates[1].ProgID != 31 || selection.Skipped != 1 || len(selection.Failures) != 1 {
		t.Fatalf("unexpected batch selection: %+v", selection)
	}

	candidatePath := filepath.Join(base, "prog29")
	selection, err = loadMismatchCandidates(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Batch || len(selection.Candidates) != 1 || selection.Candidates[0].ProgID != 29 {
		t.Fatalf("single candidate was treated as a batch: %+v", selection)
	}
}

func TestPrepareMismatchBatchWorkspace(t *testing.T) {
	reportDir := filepath.Join(t.TempDir(), "runtime-mismatches")
	legacyDir := filepath.Join(reportDir, "prog41", "bisect")
	for _, path := range []string{
		filepath.Join(legacyDir, "kernel", "built-object"),
		filepath.Join(legacyDir, "work", "image"),
		filepath.Join(legacyDir, "build.log"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	workspace, err := prepareMismatchBatchWorkspace(reportDir)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.RootDir != filepath.Join(reportDir, mismatchBatchWorkspaceName) ||
		workspace.KernelDir != filepath.Join(workspace.RootDir, "kernel") ||
		workspace.WorkDir != filepath.Join(workspace.RootDir, "work") {
		t.Fatalf("unexpected shared workspace: %+v", workspace)
	}
	if _, err := os.Stat(filepath.Join(workspace.RootDir, mismatchBatchWorkspaceMarker)); err != nil {
		t.Fatalf("workspace marker was not created: %v", err)
	}
	for _, path := range []string{filepath.Join(legacyDir, "kernel"), filepath.Join(legacyDir, "work")} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy workspace %q still exists: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(legacyDir, "build.log")); err != nil {
		t.Fatalf("per-program artifact was removed: %v", err)
	}

	sharedFile := filepath.Join(workspace.KernelDir, "keep-between-batches")
	if err := os.MkdirAll(workspace.KernelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareMismatchBatchWorkspace(reportDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sharedFile); err != nil {
		t.Fatalf("shared kernel was not reused: %v", err)
	}

	unknownReportDir := filepath.Join(t.TempDir(), "runtime-mismatches")
	unknownWorkspace := filepath.Join(unknownReportDir, mismatchBatchWorkspaceName)
	if err := os.MkdirAll(unknownWorkspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareMismatchBatchWorkspace(unknownReportDir); err == nil {
		t.Fatal("workspace without a syz-bisect marker was accepted")
	}
}

func TestPrepareSharedKernelRepoFetchesMissingEndpoint(t *testing.T) {
	baseDir := t.TempDir()
	sourceA, goodHash := makeMismatchTestRepo(t, baseDir, "source-a", "a")
	sourceB, badHash := makeMismatchTestRepo(t, baseDir, "source-b", "b")
	kernelDir := filepath.Join(baseDir, "kernel")
	if err := cloneKernelRepo(sourceA, kernelDir); err != nil {
		t.Fatal(err)
	}
	untracked := filepath.Join(kernelDir, "stale-build-output")
	if err := os.WriteFile(untracked, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo, err := vcs.NewRepo(targets.Linux, "qemu", kernelDir, vcs.OptDontSandbox)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareSharedKernelRepo(repo, sourceB, goodHash, badHash); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{goodHash, badHash} {
		present, err := repo.CommitExists(hash)
		if err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Fatalf("endpoint %s is missing from shared kernel", hash)
		}
	}
	if _, err := os.Stat(untracked); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale build output was not removed: %v", err)
	}
}

func makeMismatchTestRepo(t *testing.T, baseDir, name, contents string) (string, string) {
	t.Helper()
	dir := filepath.Join(baseDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	runMismatchTestGit(t, dir, "init")
	runMismatchTestGit(t, dir, "config", "user.email", "syz-bisect-test@example.com")
	runMismatchTestGit(t, dir, "config", "user.name", "syz-bisect test")
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	runMismatchTestGit(t, dir, "add", "file")
	runMismatchTestGit(t, dir, "commit", "-m", name)
	return dir, strings.TrimSpace(runMismatchTestGit(t, dir, "rev-parse", "HEAD"))
}

func runMismatchTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
	return string(output)
}
