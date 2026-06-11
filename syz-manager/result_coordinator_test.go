// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarizeRuntimeResultIncludesSyscallArgs(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	p := mustDeserializeProg(t, target, `ptrace(0x10, 0x17)`)

	result := summarizeRuntimeResult("v6.2", &queue.Request{Prog: p}, testResult(0, ""))

	require.Len(t, result.Calls, 1)
	call := result.Calls[0]
	assert.Equal(t, "ptrace", call.Name)
	require.Len(t, call.Args, 2)

	req := call.Args[0]
	assert.Equal(t, "req", req.Name)
	assert.Equal(t, "flags", req.Kind)
	require.NotNil(t, req.Value)
	assert.Equal(t, uint64(0x10), *req.Value)
	assert.Contains(t, req.ValueNames, "PTRACE_ATTACH")

	pid := call.Args[1]
	assert.Equal(t, "pid", pid.Name)
	assert.Equal(t, "result", pid.Kind)
	require.NotNil(t, pid.Value)
	assert.Equal(t, uint64(0x17), *pid.Value)
}

func TestSummarizeRuntimeResultIncludesPointerAndDataSummary(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	p := mustDeserializeProg(t, target,
		`write(0xffffffffffffffff, &(0x7f0000000000)='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0x28)`)

	result := summarizeRuntimeResult("v6.2", &queue.Request{Prog: p}, testResult(0, ""))

	require.Len(t, result.Calls, 1)
	require.Len(t, result.Calls[0].Args, 3)
	buf := result.Calls[0].Args[1]
	assert.Equal(t, "buf", buf.Name)
	assert.Equal(t, "ptr", buf.Kind)
	require.NotNil(t, buf.Address)
	assert.Equal(t, uint64(0), *buf.Address)
	require.Len(t, buf.Args, 1)

	data := buf.Args[0]
	assert.Equal(t, "data", data.Kind)
	require.NotNil(t, data.DataSummary)
	assert.Equal(t, uint64(40), data.DataSummary.Size)
	assert.True(t, data.DataSummary.Truncated)
	assert.Len(t, data.DataSummary.PreviewHex, 64)
	assert.NotEmpty(t, data.DataSummary.Hash)
}

func TestSummarizeRuntimeResultIncludesStructAndUnionArgs(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	p := mustDeserializeProg(t, target,
		`sendmsg$nl_xfrm(0xffffffffffffffff, &(0x7f0000000180)={0x0, 0x0, &(0x7f0000000140)={&(0x7f0000000100)=@getsadinfo={0x14, 0x23, 0x1}, 0x14}}, 0x0)`)

	result := summarizeRuntimeResult("v6.2", &queue.Request{Prog: p}, testResult(0, ""))

	require.Len(t, result.Calls, 1)
	require.Len(t, result.Calls[0].Args, 3)
	msg := result.Calls[0].Args[1]
	assert.Equal(t, "msg", msg.Name)
	assert.Equal(t, "ptr", msg.Kind)
	require.NotEmpty(t, msg.Args)
	assert.True(t, hasArgKind(msg, "struct"), "expected nested struct arg")
	assert.True(t, hasArgKind(msg, "union"), "expected nested union arg")
}

func mustDeserializeProg(t *testing.T, target *prog.Target, text string) *prog.Prog {
	t.Helper()
	p, err := target.Deserialize([]byte(strings.TrimSpace(text)), prog.NonStrict)
	require.NoError(t, err)
	return p
}

func hasArgKind(arg *runtimeCallArg, kind string) bool {
	if arg == nil {
		return false
	}
	if arg.Kind == kind {
		return true
	}
	for _, child := range arg.Args {
		if hasArgKind(child, kind) {
			return true
		}
	}
	return false
}
