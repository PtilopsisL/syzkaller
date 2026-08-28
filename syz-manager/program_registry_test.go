// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShadowProgramRegistryDistributesPrograms(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	registry := newShadowProgramRegistry()
	source := registry.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: testRegistryProg(target)}
	registry.registerPrimary("primary", primaryReq)
	primaryReq.Done(&queue.Result{Status: queue.Success})

	shadowReq := source.Next()
	require.NotNil(t, shadowReq)
	assert.Equal(t, primaryReq.ProgID, shadowReq.ProgID)
	assert.NotZero(t, shadowReq.ExecOpts.EnvFlags&flatrpc.ExecEnvSyscallTrace)
	shadowReq.Done(&queue.Result{Status: queue.Success})

	status, ok := registry.status("primary", primaryReq.ProgID)
	require.True(t, ok)
	assert.Equal(t, queue.Success, status)
	status, ok = registry.status("shadow", shadowReq.ProgID)
	require.True(t, ok)
	assert.Equal(t, queue.Success, status)
}

func TestShadowProgramRegistryLateConsumerStartsAtCurrentPosition(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	registry := newShadowProgramRegistry()
	first := &queue.Request{Prog: testRegistryProg(target)}
	registry.registerPrimary("primary", first)

	source := registry.EnsureRuntime("late", target, allSyscalls(target))

	second := &queue.Request{Prog: testRegistryProg(target)}
	registry.registerPrimary("primary", second)
	next := source.Next()
	require.NotNil(t, next)
	assert.Equal(t, second.ProgID, next.ProgID)
}

func TestShadowProgramRegistryMarksUnsupported(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	registry := newShadowProgramRegistry()
	source := registry.EnsureRuntime("shadow", target, nil)
	req := &queue.Request{Prog: testRegistryProg(target)}
	registry.registerPrimary("primary", req)
	registry.Close()

	assert.Nil(t, source.Next())
	status, ok := registry.status("shadow", req.ProgID)
	require.True(t, ok)
	assert.Equal(t, queue.Unsupported, status)
}

func TestMultiRuntimeCoordinatorSoftFirstRunLimit(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	coord.setFirstRunLimits(2, 1)
	shadowA := coord.EnsureRuntime("shadow-a", target, allSyscalls(target))
	shadowB := coord.EnsureRuntime("shadow-b", target, allSyscalls(target))

	primary := make([]*queue.Request, 3)
	for index := range primary {
		primary[index] = &queue.Request{Prog: testRegistryProg(target)}
		coord.registerPrimary("primary", primary[index])
	}

	inflight, throttled := coord.firstRunState()
	assert.Equal(t, 3, inflight)
	assert.True(t, throttled)
	assert.False(t, coord.canGenerateFirstRun())

	snapshot := coord.statsSnapshot()
	assert.Equal(t, 3, snapshot.FirstRunInflight)
	assert.True(t, snapshot.FirstRunThrottled)
	assert.Equal(t, runtimeQueueStats{FirstRun: 3}, snapshot.Queues["shadow-a"])
	assert.Equal(t, runtimeQueueStats{FirstRun: 3}, snapshot.Queues["shadow-b"])

	shadowAReqs := make([]*queue.Request, len(primary))
	shadowBReqs := make([]*queue.Request, len(primary))
	for index := range primary {
		shadowAReqs[index] = shadowA.Next()
		shadowBReqs[index] = shadowB.Next()
		require.NotNil(t, shadowAReqs[index])
		require.NotNil(t, shadowBReqs[index])
		assert.Equal(t, primary[index].ProgID, shadowAReqs[index].ProgID)
		assert.Equal(t, primary[index].ProgID, shadowBReqs[index].ProgID)
	}

	coord.mu.Lock()
	consumerA := coord.consumers["shadow-a"]
	primaryReproQueue := coord.runtimeQueueLocked("primary")
	coord.mu.Unlock()
	consumerA.enqueuePriority(&queue.Request{ProgID: 100})
	primaryReproQueue.Submit(&queue.Request{ProgID: 101})
	snapshot = coord.statsSnapshot()
	assert.Equal(t, runtimeQueueStats{Repro: 1}, snapshot.Queues["shadow-a"])
	assert.Equal(t, runtimeQueueStats{}, snapshot.Queues["shadow-b"])
	assert.Equal(t, runtimeQueueStats{Repro: 1}, snapshot.Queues["primary"])

	completeInitialRun := func(index int) {
		primary[index].Done(&queue.Result{Status: queue.Success})
		shadowAReqs[index].Done(&queue.Result{Status: queue.Success})
		shadowBReqs[index].Done(&queue.Result{Status: queue.Success})
	}
	completeInitialRun(0)
	inflight, throttled = coord.firstRunState()
	assert.Equal(t, 2, inflight)
	assert.True(t, throttled)

	completeInitialRun(1)
	inflight, throttled = coord.firstRunState()
	assert.Equal(t, 1, inflight)
	assert.False(t, throttled)
	assert.True(t, coord.canGenerateFirstRun())
}

func TestMultiRuntimeCoordinatorContinuesProgIDFromReservedState(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	workdir := t.TempDir()
	coord := newMultiRuntimeCoordinator(workdir)
	first := &queue.Request{Prog: testRegistryProg(target)}
	coord.registerPrimary("primary", first)
	require.EqualValues(t, 1, first.ProgID)

	reserved, err := loadProgIDState(progIDStatePath(workdir))
	require.NoError(t, err)
	require.GreaterOrEqual(t, reserved, int64(progIDReserveBatch))

	restarted := newMultiRuntimeCoordinator(workdir)
	next := &queue.Request{Prog: testRegistryProg(target)}
	restarted.registerPrimary("primary", next)
	assert.Equal(t, reserved+1, next.ProgID)
}

func TestMultiRuntimeCoordinatorContinuesProgIDFromArtifacts(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	workdir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "runtime-mismatches", "prog12-repro15"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "runtime-mismatches", "custom"), 0o755))
	report := []byte(`{"parent_prog_id":48,"repro_prog_id":49}`)
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "runtime-mismatches", "custom", "report.json"),
		report, 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "runtime-unstable", "prog50-repro51"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "strace-log"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "strace-log", "strace.prog31.2.log"), nil, 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "runtimes", "shadow", "strace-log"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "runtimes", "shadow", "strace-log",
		"strace.prog42.1.log"), nil, 0o644))

	coord := newMultiRuntimeCoordinator(workdir)
	req := &queue.Request{Prog: testRegistryProg(target)}
	coord.registerPrimary("primary", req)
	assert.EqualValues(t, 52, req.ProgID)
}

func TestMultiRuntimeCoordinatorSchedulesMismatchRepro(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	primaryBase := queue.Plain()
	primarySource := coord.sourceForRuntime("primary", primaryBase)
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)}
	coord.registerPrimary("primary", primaryReq)
	shadowReq := shadowSource.Next()
	require.NotNil(t, shadowReq)

	primaryReq.Done(testResult(0, "0: test() = 0 {0}\n"))
	shadowReq.Done(testResult(1, "0: test() = -1 {1}\n"))

	var reproID int64
	for i := range mismatchReproRuns {
		primaryRepro := primarySource.Next()
		require.NotNil(t, primaryRepro)
		shadowRepro := shadowSource.Next()
		require.NotNil(t, shadowRepro)
		if i == 0 {
			reproID = primaryRepro.ProgID
			assert.NotEqual(t, primaryReq.ProgID, reproID)
		}
		assert.Equal(t, reproID, primaryRepro.ProgID)
		assert.Equal(t, reproID, shadowRepro.ProgID)
		assert.NotZero(t, primaryRepro.ExecOpts.EnvFlags&flatrpc.ExecEnvSyscallTrace)
		assert.NotZero(t, shadowRepro.ExecOpts.EnvFlags&flatrpc.ExecEnvSyscallTrace)
		assert.Equal(t, 0, coord.reproQueueLen("primary"))
		assert.Equal(t, 0, coord.reproQueueLen("shadow"))
		primaryRepro.Done(testResult(0, "0: test() = 0 {0}\n"))
		if i+1 < mismatchReproRuns {
			assert.Equal(t, 1, coord.reproQueueLen("primary"))
		}
		shadowRepro.Done(testResult(1, "0: test() = -1 {1}\n"))
		if i+1 < mismatchReproRuns {
			assert.Equal(t, 1, coord.reproQueueLen("shadow"))
		}
	}
	preMinimizeDir := runtimeReportDir(coord.store.baseDir, primaryReq.ProgID, reproID)
	assert.FileExists(t, filepath.Join(preMinimizeDir, "report.json"))
	assert.FileExists(t, filepath.Join(preMinimizeDir, "repro.prog"))

	var minimizedID int64
	for index := range mismatchReproRuns {
		primaryMinimized := nextRequestEventually(t, primarySource)
		shadowMinimized := nextRequestEventually(t, shadowSource)
		if index == 0 {
			minimizedID = primaryMinimized.ProgID
		}
		assert.Equal(t, minimizedID, primaryMinimized.ProgID)
		assert.Equal(t, minimizedID, shadowMinimized.ProgID)
		assert.Equal(t, 1, len(primaryMinimized.Prog.Calls))
		assert.Equal(t, 1, len(shadowMinimized.Prog.Calls))
		primaryMinimized.Done(testResult(0, "0: test() = 0 {0}\n"))
		shadowMinimized.Done(testResult(1, "0: test() = -1 {1}\n"))
	}
	require.Eventually(t, func() bool {
		entries, err := os.ReadDir(coord.store.baseDir)
		if err != nil || len(entries) != 2 {
			return false
		}
		_, err = os.Stat(filepath.Join(runtimeReportDir(coord.store.baseDir,
			primaryReq.ProgID, minimizedID), "report.json"))
		return err == nil
	}, time.Second, time.Millisecond)

	entries, err := os.ReadDir(filepath.Join(coord.store.baseDir))
	require.NoError(t, err)
	require.Len(t, entries, 2)
	reportDir := runtimeReportDir(coord.store.baseDir, primaryReq.ProgID, minimizedID)
	assert.NoDirExists(t, coord.unstableStore.baseDir)
	reportPath := filepath.Join(reportDir, "report.json")
	assert.FileExists(t, reportPath)
	assert.FileExists(t, filepath.Join(reportDir, "repro.prog"))
	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"sctrace"`)
	assert.NotContains(t, string(data), "\n")
	var report storedMismatchReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.Equal(t, storedMismatchReportFormatVersion, report.FormatVersion)
	expectedTraceFiles := []string{
		"logs/primary.initial.strace.log",
		"logs/primary.sample1.strace.log",
		"logs/primary.sample2.strace.log",
		"logs/primary.sample3.strace.log",
		"logs/shadow.initial.strace.log",
		"logs/shadow.sample1.strace.log",
		"logs/shadow.sample2.strace.log",
		"logs/shadow.sample3.strace.log",
	}
	assert.ElementsMatch(t, expectedTraceFiles, report.TraceFiles)
	for _, traceFile := range expectedTraceFiles {
		assert.FileExists(t, filepath.Join(reportDir, filepath.FromSlash(traceFile)))
	}
	require.NotEmpty(t, report.ProgramCalls)
	assert.NotEmpty(t, report.ProgramCalls[0].Args)
	for _, result := range report.InitialResults {
		require.NotEmpty(t, result.Calls)
		assert.Empty(t, result.Calls[0].Args)
		assert.Empty(t, result.Calls[0].Sctrace)
	}
	require.NotEmpty(t, report.ReproSamples)
	for _, samples := range report.ReproSamples {
		require.Len(t, samples, mismatchReproRuns)
		for _, result := range samples {
			require.NotEmpty(t, result.Calls)
			assert.Empty(t, result.Calls[0].Args)
			assert.Empty(t, result.Calls[0].Sctrace)
		}
	}
}

func TestMultiRuntimeCoordinatorMinimizesFirstMismatchSyscall(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	primarySource := coord.sourceForRuntime("primary", queue.Plain())
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))
	program := mustDeserializeProg(t, target, `getpid()
ptrace(0x10, 0x17)
getpid()`)

	primary := &queue.Request{Prog: program}
	coord.registerPrimary("primary", primary)
	shadow := nextRequestEventually(t, shadowSource)
	primary.Done(testProgramResult(primary, 1))
	shadow.Done(testProgramResult(shadow, 9))

	completeCandidate := func(wantCalls, runs int) int64 {
		var progID int64
		for range runs {
			primaryCandidate := nextRequestEventually(t, primarySource)
			shadowCandidate := nextRequestEventually(t, shadowSource)
			if progID == 0 {
				progID = primaryCandidate.ProgID
			}
			assert.Equal(t, progID, primaryCandidate.ProgID)
			assert.Equal(t, progID, shadowCandidate.ProgID)
			assert.Equal(t, wantCalls, len(primaryCandidate.Prog.Calls))
			assert.Equal(t, primaryCandidate.Prog.Serialize(), shadowCandidate.Prog.Serialize())
			primaryCandidate.Done(testProgramResult(primaryCandidate, 1))
			shadowCandidate.Done(testProgramResult(shadowCandidate, 9))
		}
		return progID
	}

	// The first repro run is the baseline used to start minimization.
	preMinimizeID := completeCandidate(len(program.Calls), mismatchReproRuns)
	// The minimizer removes the trailing unrelated call, then the leading one.
	completeCandidate(2, mismatchMinimizeCandidateRuns)
	completeCandidate(1, mismatchMinimizeCandidateRuns)
	// The final three samples validate the program that will be saved.
	postMinimizeID := completeCandidate(1, mismatchReproRuns)

	var entries []os.DirEntry
	require.Eventually(t, func() bool {
		entries, err = os.ReadDir(coord.store.baseDir)
		if err != nil || len(entries) != 2 {
			return false
		}
		_, err = os.Stat(filepath.Join(runtimeReportDir(coord.store.baseDir,
			primary.ProgID, postMinimizeID), "report.json"))
		return err == nil
	}, time.Second, time.Millisecond)

	preData, err := os.ReadFile(filepath.Join(runtimeReportDir(coord.store.baseDir,
		primary.ProgID, preMinimizeID), "report.json"))
	require.NoError(t, err)
	var preReport storedMismatchReport
	require.NoError(t, json.Unmarshal(preData, &preReport))
	assert.Equal(t, primary.ProgID, preReport.ParentProgID)
	assert.Equal(t, preMinimizeID, preReport.ReproProgID)
	assert.Len(t, preReport.ProgramCalls, len(program.Calls))
	assert.Equal(t, "ptrace", preReport.ProgramCalls[1].Name)
	require.NotEmpty(t, preReport.StableDifferences)
	assert.Equal(t, 1, *preReport.StableDifferences[0].CallIndex)

	data, err := os.ReadFile(filepath.Join(runtimeReportDir(coord.store.baseDir,
		primary.ProgID, postMinimizeID), "report.json"))
	require.NoError(t, err)
	var report storedMismatchReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.Equal(t, primary.ProgID, report.ParentProgID)
	assert.Equal(t, postMinimizeID, report.ReproProgID)
	assert.Len(t, report.ProgramCalls, 1)
	assert.Equal(t, "ptrace", report.ProgramCalls[0].Name)
	require.NotEmpty(t, report.StableDifferences)
	assert.Equal(t, 0, *report.StableDifferences[0].CallIndex)
}

func TestMultiRuntimeCoordinatorUsesComparisonPrimary(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	workdir := t.TempDir()
	coord := newMultiRuntimeCoordinator(workdir)
	coord.setComparisonPrimary("primary-comparison", "primary")
	coord.setRuntimeVersion("primary-comparison", "6.2")
	coord.setRuntimeVersion("shadow", "6.1")
	dirtyPrimarySource := coord.sourceForRuntime("primary-fuzzing", queue.Plain())
	comparisonSource := coord.EnsureRuntime("primary-comparison", target, allSyscalls(target))
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)}
	coord.registerPrimary("primary-fuzzing", primaryReq)
	comparisonReq := comparisonSource.Next()
	shadowReq := shadowSource.Next()
	require.NotNil(t, comparisonReq)
	require.NotNil(t, shadowReq)

	// The fuzzing primary result is recorded for observability, but it does not
	// participate in either the initial comparison or mismatch reproduction.
	primaryReq.Done(testResult(7, "0: dirty() = -1 {7}\n"))
	comparisonReq.Done(testResult(0, "0: test() = 0 {0}\n"))
	shadowReq.Done(testResult(1, "0: test() = -1 {1}\n"))

	assert.Nil(t, dirtyPrimarySource.Next())
	assert.Zero(t, coord.reproQueueLen("primary-fuzzing"))
	var preMinimizeID int64
	for index := range mismatchReproRuns {
		comparisonRepro := comparisonSource.Next()
		shadowRepro := shadowSource.Next()
		require.NotNil(t, comparisonRepro)
		require.NotNil(t, shadowRepro)
		if index == 0 {
			preMinimizeID = comparisonRepro.ProgID
		}
		assert.Equal(t, preMinimizeID, comparisonRepro.ProgID)
		assert.Equal(t, preMinimizeID, shadowRepro.ProgID)
		comparisonRepro.Done(testResult(0, "0: test() = 0 {0}\n"))
		shadowRepro.Done(testResult(1, "0: test() = -1 {1}\n"))
	}
	var postMinimizeID int64
	for index := range mismatchReproRuns {
		comparisonMinimized := nextRequestEventually(t, comparisonSource)
		shadowMinimized := nextRequestEventually(t, shadowSource)
		if index == 0 {
			postMinimizeID = comparisonMinimized.ProgID
		}
		assert.Equal(t, postMinimizeID, comparisonMinimized.ProgID)
		assert.Equal(t, postMinimizeID, shadowMinimized.ProgID)
		comparisonMinimized.Done(testResult(0, "0: test() = 0 {0}\n"))
		shadowMinimized.Done(testResult(1, "0: test() = -1 {1}\n"))
	}
	require.Eventually(t, func() bool {
		entries, err := os.ReadDir(filepath.Join(workdir, "runtime-mismatches"))
		if err != nil || len(entries) != 2 {
			return false
		}
		_, err = os.Stat(filepath.Join(runtimeReportDir(filepath.Join(workdir, "runtime-mismatches"),
			primaryReq.ProgID, postMinimizeID), "report.json"))
		return err == nil
	}, time.Second, time.Millisecond)

	entries, err := os.ReadDir(filepath.Join(workdir, "runtime-mismatches"))
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.FileExists(t, filepath.Join(runtimeReportDir(filepath.Join(workdir, "runtime-mismatches"),
		primaryReq.ProgID, preMinimizeID), "report.json"))
	data, err := os.ReadFile(filepath.Join(runtimeReportDir(filepath.Join(workdir, "runtime-mismatches"),
		primaryReq.ProgID, postMinimizeID), "report.json"))
	require.NoError(t, err)
	var report storedMismatchReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.ElementsMatch(t, []string{"primary", "shadow"}, report.Runtimes)
	assert.Contains(t, report.InitialResults, "primary")
	assert.NotContains(t, report.InitialResults, "primary-comparison")
	assert.Contains(t, report.ReproSamples, "primary")
	assert.NotContains(t, report.ReproSamples, "primary-comparison")
	assert.Contains(t, report.Compared, "primary")
	assert.NotContains(t, report.Compared, "primary-comparison")
	assert.Contains(t, report.TraceFiles, "logs/primary.initial.strace.log")
	assert.True(t, runtimeDiffLabelScopeMatches(runtimeDiffLabelScope{
		RuntimeNames: []string{"primary", "shadow"},
		RuntimeVersions: map[string]string{
			"primary": "6.2",
			"shadow":  "6.1",
		},
	}, report.ReproSamples))
}

func TestMismatchStoreOmitsEmptyTraceManifest(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	p := mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)
	run := &programRun{
		ID:        2,
		ParentID:  1,
		Prog:      p,
		ProgData:  p.Serialize(),
		Samples:   map[string][]*runtimeResult{},
		ReproRuns: mismatchReproRuns,
		InitialResults: map[string]*runtimeResult{
			"primary": {
				Runtime: "primary",
				Status:  queue.Success,
				Calls: []runtimeCallResult{{
					Index: 0,
					Name:  p.CallName(0),
					Args:  summarizeCallArgs(p, 0),
				}},
			},
		},
	}
	store := newMismatchStore(t.TempDir())
	dir, err := store.Save(run, &runtimeMismatch{
		Outcome:  comparisonOutcomeMismatch,
		Reason:   "test mismatch",
		Runtimes: []string{"primary", "shadow"},
	})
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	require.NoError(t, err)
	var report storedMismatchReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.Empty(t, report.TraceFiles)
	require.NotEmpty(t, report.ProgramCalls)
	assert.NotEmpty(t, report.ProgramCalls[0].Args)
	entries, err := os.ReadDir(filepath.Join(dir, "logs"))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestMultiRuntimeCoordinatorBalancesPriorityAndNormalShadowWork(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))
	normalReq := &queue.Request{Prog: testRegistryProg(target)}
	coord.registerPrimary("primary", normalReq)

	coord.mu.Lock()
	consumer := coord.consumers["shadow"]
	coord.mu.Unlock()
	for index := range shadowPriorityBurst + 1 {
		consumer.enqueuePriority(&queue.Request{ProgID: int64(100 + index)})
	}

	for index := range shadowPriorityBurst {
		req := shadowSource.Next()
		require.NotNil(t, req)
		assert.Equal(t, int64(100+index), req.ProgID)
	}
	req := shadowSource.Next()
	require.NotNil(t, req)
	assert.Equal(t, normalReq.ProgID, req.ProgID)
	req = shadowSource.Next()
	require.NotNil(t, req)
	assert.Equal(t, int64(100+shadowPriorityBurst), req.ProgID)
}

func TestMultiRuntimeCoordinatorEmptyShadowDoesNotBlock(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	next := make(chan *queue.Request, 1)
	go func() {
		next <- shadowSource.Next()
	}()
	select {
	case req := <-next:
		assert.Nil(t, req)
	case <-time.After(time.Second):
		coord.Close()
		t.Fatal("empty shadow source blocked")
	}

	primaryReq := &queue.Request{Prog: testRegistryProg(target)}
	coord.registerPrimary("primary", primaryReq)
	shadowReq := shadowSource.Next()
	require.NotNil(t, shadowReq)
	assert.Equal(t, primaryReq.ProgID, shadowReq.ProgID)
}

func TestMultiRuntimeCoordinatorQueuesShadowPriorityRepro(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)}
	coord.registerPrimary("primary", primaryReq)
	shadowReq := shadowSource.Next()
	require.NotNil(t, shadowReq)

	primaryReq.Done(testResult(0, ""))
	shadowReq.Done(testResult(1, ""))

	reproReq := shadowSource.Next()
	require.NotNil(t, reproReq)
	assert.NotEqual(t, primaryReq.ProgID, reproReq.ProgID)
}

func TestMultiRuntimeCoordinatorPersistsUnstableResultsSeparately(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	workdir := t.TempDir()
	coord := newMultiRuntimeCoordinator(workdir)
	primaryBase := queue.Plain()
	primarySource := coord.sourceForRuntime("primary", primaryBase)
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)}
	coord.registerPrimary("primary", primaryReq)
	shadowReq := shadowSource.Next()
	require.NotNil(t, shadowReq)

	primaryReq.Done(testResult(1, ""))
	shadowReq.Done(testResult(9, ""))

	primaryErrnos := []int32{1, 2, 3}
	for i := range mismatchReproRuns {
		primaryRepro := primarySource.Next()
		require.NotNil(t, primaryRepro)
		shadowRepro := shadowSource.Next()
		require.NotNil(t, shadowRepro)
		primaryRepro.Done(testResult(primaryErrnos[i], ""))
		shadowRepro.Done(testResult(9, ""))
	}

	assert.NoFileExists(t, coord.store.baseDir)
	entries, err := os.ReadDir(coord.unstableStore.baseDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	reportPath := filepath.Join(coord.unstableStore.baseDir, entries[0].Name(), "report.json")
	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var report storedMismatchReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.Equal(t, comparisonOutcomeInconclusive, report.Outcome)
	assert.Empty(t, report.StableDifferences)
	assert.Contains(t, report.UnstableFields["primary"], "calls[0].error")
	require.Len(t, report.ReproSamples["primary"], mismatchReproRuns)
	require.Len(t, report.ReproSamples["shadow"], mismatchReproRuns)
}

func TestMultiRuntimeCoordinatorIgnoresLegacyNoiseRules(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	workdir := t.TempDir()
	legacyRules := []byte(`{"version":1,"syscalls":{"ptrace":{"ignore":{"errno":true}}}}`)
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "runtime-noise.json"), legacyRules, 0o644))
	coord := newMultiRuntimeCoordinator(workdir)
	primaryBase := queue.Plain()
	primarySource := coord.sourceForRuntime("primary", primaryBase)
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)}
	coord.registerPrimary("primary", primaryReq)
	shadowReq := shadowSource.Next()
	require.NotNil(t, shadowReq)
	primaryReq.Done(testResult(1, ""))
	shadowReq.Done(testResult(9, ""))

	assert.NotNil(t, primarySource.Next(), "legacy noise rules must not suppress repro")
}

func TestMultiRuntimeCoordinatorIgnoresMatchingResults(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	primaryBase := queue.Plain()
	primarySource := coord.sourceForRuntime("primary", primaryBase)
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: testRegistryProg(target)}
	coord.registerPrimary("primary", primaryReq)
	shadowReq := shadowSource.Next()
	require.NotNil(t, shadowReq)

	primaryReq.Done(testResult(0, "0: test() = 0 {0}\n"))
	shadowReq.Done(testResult(0, "0: test() = 0 {0}\n"))

	assert.Nil(t, primarySource.Next())
	assert.Equal(t, 0, coord.reproQueueLen("shadow"))
	assert.NoFileExists(t, coord.store.baseDir)
}

func TestMultiRuntimeCoordinatorDoesNotReproUnsupported(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	primaryBase := queue.Plain()
	primarySource := coord.sourceForRuntime("primary", primaryBase)
	shadowSource := coord.EnsureRuntime("shadow", target, nil)

	primaryReq := &queue.Request{Prog: testRegistryProg(target)}
	coord.registerPrimary("primary", primaryReq)
	coord.Close()

	assert.Nil(t, shadowSource.Next())
	primaryReq.Done(testResult(0, "0: test() = 0 {0}\n"))

	assert.Nil(t, primarySource.Next())
	assert.NoFileExists(t, coord.store.baseDir)
}

func testResult(errno int32, sctrace string) *queue.Result {
	returnValue := int64(0)
	if errno != 0 {
		returnValue = -1
	}
	return &queue.Result{
		Status: queue.Success,
		Info: &flatrpc.ProgInfo{
			Calls: []*flatrpc.CallInfo{
				{
					Flags:            flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
					Error:            errno,
					ReturnValue:      returnValue,
					ReturnValueValid: true,
					Sctrace:          []byte(sctrace),
				},
			},
		},
	}
}

func testProgramResult(req *queue.Request, mismatchErrno int32) *queue.Result {
	info := &flatrpc.ProgInfo{}
	for index := range req.Prog.Calls {
		errno := int32(0)
		if req.Prog.CallName(index) == "ptrace" {
			errno = mismatchErrno
		}
		returnValue := int64(0)
		if errno != 0 {
			returnValue = -1
		}
		info.Calls = append(info.Calls, &flatrpc.CallInfo{
			Flags:            flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			Error:            errno,
			ReturnValue:      returnValue,
			ReturnValueValid: true,
		})
	}
	return &queue.Result{
		Status: queue.Success,
		Info:   info,
	}
}

func nextRequestEventually(t *testing.T, source queue.Source) *queue.Request {
	t.Helper()
	var req *queue.Request
	require.Eventually(t, func() bool {
		req = source.Next()
		return req != nil
	}, time.Second, time.Millisecond)
	return req
}

func testRegistryProg(target *prog.Target) *prog.Prog {
	return target.Generate(mathrand.NewSource(0), 1, target.DefaultChoiceTable())
}

func runtimeReportDir(baseDir string, parentID, reproID int64) string {
	return filepath.Join(baseDir, fmt.Sprintf("prog%d-repro%d", parentID, reproID))
}

func allSyscalls(target *prog.Target) map[*prog.Syscall]bool {
	ret := make(map[*prog.Syscall]bool, len(target.Syscalls))
	for _, call := range target.Syscalls {
		ret[call] = true
	}
	return ret
}
