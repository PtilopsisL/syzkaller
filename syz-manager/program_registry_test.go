// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"testing"

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
	reportPath := filepath.Join(coord.store.baseDir, entries[0].Name(), "report.json")
	assert.FileExists(t, reportPath)
	assert.FileExists(t, filepath.Join(coord.store.baseDir, entries[0].Name(), "repro.prog"))
	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var report storedMismatchReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.NotEmpty(t, report.ReproSamples)
	for _, samples := range report.ReproSamples {
		require.Len(t, samples, mismatchReproRuns)
		for _, result := range samples {
			require.NotEmpty(t, result.Calls)
			assert.NotEmpty(t, result.Calls[0].Args)
		}
	}
}

func TestMultiRuntimeCoordinatorLearnsAndAppliesNoise(t *testing.T) {
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

	rules := coord.noise.snapshot()
	require.Contains(t, rules.Syscalls, "ptrace")
	assert.True(t, rules.Syscalls["ptrace"].Ignore.Errno)
	assert.FileExists(t, filepath.Join(workdir, noiseRuleFileName))
	assert.NoFileExists(t, coord.store.baseDir)
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
	return &queue.Result{
		Status: queue.Success,
		Info: &flatrpc.ProgInfo{
			Calls: []*flatrpc.CallInfo{
				{
					Flags:   flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
					Error:   errno,
					Sctrace: []byte(sctrace),
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
