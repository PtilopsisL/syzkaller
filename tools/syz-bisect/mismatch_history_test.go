// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

func TestAnalyzeMismatchHistoryAncestry(t *testing.T) {
	t.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
	const date = "2002-01-01T00:00:00Z"
	t.Setenv("GIT_AUTHOR_DATE", date)
	t.Setenv("GIT_COMMITTER_DATE", date)
	for _, test := range []struct {
		name          string
		clockSkew     bool
		separateRepos bool
		merge         bool
		fork          bool
		conflict      bool
		wantError     string
	}{
		{name: "clock_skew", clockSkew: true},
		{name: "same_timestamp"},
		{name: "separate_repositories", separateRepos: true, clockSkew: true},
		{name: "merge_second_parent", merge: true},
		{name: "diverging_branches", fork: true, wantError: "not on one ancestry chain"},
		{name: "conflicting_duplicate", conflict: true, wantError: "disagree at commit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseDir := t.TempDir()
			source, oldest := makeMismatchTestRepo(t, baseDir, "kernel", "old")
			oldSource := source
			if test.separateRepos {
				// Clone before adding the descendants: only the newer runtime's
				// repository will contain the entire observed history.
				oldSource = filepath.Join(baseDir, "old-kernel")
				runMismatchTestGit(t, baseDir, "clone", "--no-local", source, oldSource)
			}
			middleDate, newestDate := date, date
			if test.clockSkew {
				middleDate = "2003-01-01T00:00:00Z"
				newestDate = "2001-01-01T00:00:00Z"
			}
			middle := makeMismatchHistoryCommit(t, source, "middle", middleDate, oldest)
			parents := []string{middle}
			if test.fork {
				parents = []string{oldest}
			} else if test.merge {
				side := makeMismatchHistoryCommit(t, source, "side", date, oldest)
				parents = []string{side, middle}
			}
			newest := makeMismatchHistoryCommit(t, source, "newest", newestDate, parents...)
			versions := map[string]string{
				"old": oldest, "middle": middle, "new": newest, "old-copy": oldest,
			}
			cfg := &mgrconfig.Config{RuntimeConfigs: make(map[string]*mgrconfig.Config)}
			for name, version := range versions {
				kernelSource := source
				if name == "old" || name == "old-copy" {
					kernelSource = oldSource
				}
				cfg.RuntimeConfigs[name] = &mgrconfig.Config{
					KernelSrc: kernelSource, KernelVersion: version, Type: "qemu",
					Derived: mgrconfig.Derived{TargetOS: targets.Linux},
				}
			}
			values := map[string]json.RawMessage{
				"old": json.RawMessage("0"), "middle": json.RawMessage("0"),
				"new": json.RawMessage("2"), "old-copy": json.RawMessage("0"),
			}
			if test.conflict {
				values["old-copy"] = json.RawMessage("2")
			}
			candidate := &mismatchCandidate{Report: storedMismatchForBisect{
				// Deliberately neither chronological nor ancestry order, with
				// non-adjacent duplicate observations of the oldest commit.
				Runtimes: []string{"old", "new", "old-copy", "middle"},
				StableDifferences: []storedMismatchDifference{{
					Kind: "status", Path: "status", Values: values,
				}},
			}}
			// Analyzing history must leave the live runtime checkout untouched.
			const dirtyContents = "uncommitted runtime changes"
			if err := os.WriteFile(filepath.Join(source, "file"), []byte(dirtyContents), 0o644); err != nil {
				t.Fatal(err)
			}
			err := analyzeMismatchHistory(candidate, cfg)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("analyzeMismatchHistory = %v, want %q", err, test.wantError)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				history := candidate.History
				if len(history.Points) != 3 || history.Pattern != "AAB" ||
					history.Good.Commit.Hash != middle || history.Bad.Commit.Hash != newest {
					t.Fatalf("unexpected history: %+v", history)
				}
				for index, hash := range []string{oldest, middle, newest} {
					if history.Points[index].Commit.Hash != hash {
						t.Fatalf("point %d = %s, want %s", index, history.Points[index].Commit.Hash, hash)
					}
				}
			}
			if head := strings.TrimSpace(runMismatchTestGit(t, source, "rev-parse", "HEAD")); head != oldest {
				t.Fatalf("runtime checkout moved from %s to %s", oldest, head)
			}
			data, err := os.ReadFile(filepath.Join(source, "file"))
			if err != nil || string(data) != dirtyContents {
				t.Fatalf("runtime changes were modified: %q, %v", data, err)
			}
		})
	}
}

func makeMismatchHistoryCommit(t *testing.T, dir, title, date string, parents ...string) string {
	t.Helper()
	tree := strings.TrimSpace(runMismatchTestGit(t, dir, "rev-parse", "HEAD^{tree}"))
	args := []string{"commit-tree", tree, "-m", title}
	for _, parent := range parents {
		args = append(args, "-p", parent)
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git commit-tree failed: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(output))
}
