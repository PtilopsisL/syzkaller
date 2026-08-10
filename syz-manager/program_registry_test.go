// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
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
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "strace-log"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "strace-log", "strace.prog31.2.log"), nil, 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "runtimes", "shadow", "strace-log"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "runtimes", "shadow", "strace-log",
		"strace.prog42.1.log"), nil, 0o644))

	coord := newMultiRuntimeCoordinator(workdir)
	req := &queue.Request{Prog: testRegistryProg(target)}
	coord.registerPrimary("primary", req)
	assert.EqualValues(t, 50, req.ProgID)
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

	entries, err := os.ReadDir(filepath.Join(coord.store.baseDir))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	reportDir := filepath.Join(coord.store.baseDir, entries[0].Name())
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

func TestMultiRuntimeCoordinatorWakesAllShadowPriorityWaiters(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))
	coord.mu.Lock()
	consumer := coord.consumers["shadow"]
	coord.mu.Unlock()

	const requestCount = 8
	results := make(chan *queue.Request, requestCount)
	for range requestCount {
		go func() {
			results <- shadowSource.Next()
		}()
	}
	for index := range requestCount {
		consumer.enqueuePriority(&queue.Request{ProgID: int64(100 + index)})
	}

	seen := map[int64]bool{}
	for range requestCount {
		select {
		case req := <-results:
			require.NotNil(t, req)
			seen[req.ProgID] = true
		case <-time.After(time.Second):
			coord.Close()
			t.Fatal("not all shadow waiters were woken for queued priority requests")
		}
	}
	assert.Len(t, seen, requestCount)
	assert.Equal(t, 0, consumer.priorityLen())
}

func TestMultiRuntimeCoordinatorWakesShadowForPriorityRepro(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	coord := newMultiRuntimeCoordinator(t.TempDir())
	shadowSource := coord.EnsureRuntime("shadow", target, allSyscalls(target))

	primaryReq := &queue.Request{Prog: mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)}
	coord.registerPrimary("primary", primaryReq)
	shadowReq := shadowSource.Next()
	require.NotNil(t, shadowReq)

	primaryReq.Done(testResult(0, ""))
	next := make(chan *queue.Request, 1)
	go func() {
		next <- shadowSource.Next()
	}()
	shadowReq.Done(testResult(1, ""))

	select {
	case reproReq := <-next:
		require.NotNil(t, reproReq)
		assert.NotEqual(t, primaryReq.ProgID, reproReq.ProgID)
	case <-time.After(time.Second):
		coord.Close()
		t.Fatal("shadow source was not woken for a queued repro request")
	}
}

func TestMultiRuntimeCoordinatorDoesNotPersistUnstableResults(t *testing.T) {
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

	assert.NoFileExists(t, filepath.Join(workdir, "runtime-noise.json"))
	assert.NoFileExists(t, coord.store.baseDir)
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

func testRegistryProg(target *prog.Target) *prog.Prog {
	return target.Generate(mathrand.NewSource(0), 1, target.DefaultChoiceTable())
}

func allSyscalls(target *prog.Target) map[*prog.Syscall]bool {
	ret := make(map[*prog.Syscall]bool, len(target.Syscalls))
	for _, call := range target.Syscalls {
		ret[call] = true
	}
	return ret
}
