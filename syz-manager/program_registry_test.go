// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	mathrand "math/rand"
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
