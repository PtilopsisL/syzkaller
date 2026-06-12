// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
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

func TestSummarizeRuntimeResultDecodesReturnAndOutputArgs(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	p := mustDeserializeProg(t, target,
		`pipe2(&(0x7f0000000000)={<r0=>0x0, <r1=>0x0}, 0x0)`)
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:], 11)
	binary.LittleEndian.PutUint32(data[4:], 22)
	res := testResult(0, "")
	res.Info.Calls[0].ReturnValue = 0
	res.Info.Calls[0].ReturnValueValid = true
	res.Info.Calls[0].Outputs = []*flatrpc.OutputCapture{{
		Id:   0,
		Data: data,
	}}
	req := &queue.Request{
		Prog: p,
		ExecOpts: flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectOutputs,
		},
	}

	result := summarizeRuntimeResult("v6.2", req, res)

	call := result.Calls[0]
	require.NotNil(t, call.ReturnValue)
	assert.Equal(t, int64(0), *call.ReturnValue)
	require.Len(t, call.Outputs, 1)
	output := call.Outputs[0]
	assert.Equal(t, "arg[0]", output.Path)
	assert.Equal(t, "pipefd", output.Type)
	assert.Equal(t, uint64(8), output.CapturedSize)
	require.Len(t, output.Values, 2)
	assert.Equal(t, "arg[0].rfd", output.Values[0].Path)
	assert.Equal(t, "fd", output.Values[0].Type)
	require.NotNil(t, output.Values[0].Value)
	assert.Equal(t, uint64(11), *output.Values[0].Value)
	assert.Equal(t, "arg[0].wfd", output.Values[1].Path)
	require.NotNil(t, output.Values[1].Value)
	assert.Equal(t, uint64(22), *output.Values[1].Value)
}

func TestCompareRuntimeResultsUsesDecodedValuesNotSctrace(t *testing.T) {
	base := &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{{
			Index:       0,
			Name:        "pipe2",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
			Sctrace:     "runtime-specific text",
			Outputs: []*runtimeOutputCapture{{
				ID: 0,
				Values: []*runtimeDecodedOutput{{
					Path:  "arg[0].rfd",
					Type:  "fd",
					Dir:   "out",
					Kind:  "result",
					Value: uint64Ptr(11),
				}},
			}},
		}},
	}
	same := *base
	same.Calls = append([]runtimeCallResult(nil), base.Calls...)
	same.Calls[0].Sctrace = "different formatting"

	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"a": base,
		"b": &same,
	}))

	different := same
	different.Calls = append([]runtimeCallResult(nil), same.Calls...)
	different.Calls[0].Outputs = cloneRuntimeOutputCaptures(same.Calls[0].Outputs)
	different.Calls[0].Outputs[0].Values[0].Value = uint64Ptr(12)
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"a": base,
		"b": &different,
	}))
}

func TestSummarizeOutputDataKeepsPartialCapture(t *testing.T) {
	summary := summarizeOutputData([]byte("abcdefghijklmnop"), 64)

	assert.Equal(t, uint64(64), summary.Size)
	assert.Equal(t, uint64(16), summary.CapturedSize)
	assert.True(t, summary.Truncated)
	assert.NotEmpty(t, summary.Hash)
	assert.Equal(t, "6162636465666768696a6b6c6d6e6f70", summary.PreviewHex)
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
