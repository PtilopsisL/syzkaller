// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
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

func TestFirstRuntimeMismatchCallIdentityTracksCallRemoval(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	original := mustDeserializeProg(t, target, `getpid()
ptrace(0x10, 0x17)
getpid()`)
	secondCall, thirdCall := 1, 2
	baseValues := map[string]any{"primary": int32(1), "shadow": int32(9)}
	baseMismatch := &runtimeMismatch{
		Outcome: comparisonOutcomeMismatch,
		StableDifferences: []runtimeFieldDifference{
			{
				Kind: "errno", Path: "calls[1].error", Values: baseValues,
				CallIndex: &secondCall,
			},
			{
				Kind: "return_value", Path: "calls[1].return_value",
				Values:    map[string]any{"primary": int64(-1), "shadow": int64(0)},
				CallIndex: &secondCall,
			},
			{
				Kind: "errno", Path: "calls[2].error",
				Values:    map[string]any{"primary": int32(0), "shadow": int32(0)},
				CallIndex: &thirdCall,
			},
		},
	}

	identity, callIndex, ok := firstRuntimeMismatchCallIdentity(original, baseMismatch)
	require.True(t, ok)
	assert.Equal(t, 1, callIndex)
	assert.Equal(t, "ptrace", identity.CallName)
	assert.Len(t, identity.Differences, 2)

	candidate := original.Clone()
	candidate.RemoveCall(0)
	candidateCall := 0
	candidateMismatch := &runtimeMismatch{
		Outcome: comparisonOutcomeMismatch,
		StableDifferences: []runtimeFieldDifference{
			{
				Kind: "errno", Path: "calls[0].error", Values: baseValues,
				CallIndex: &candidateCall,
			},
			{
				Kind: "return_value", Path: "calls[0].return_value",
				Values:    map[string]any{"primary": int64(-1), "shadow": int64(0)},
				CallIndex: &candidateCall,
			},
		},
	}
	assert.True(t, identity.matches(candidate, candidateMismatch, candidateCall))

	candidateMismatch.StableDifferences[0].Values = map[string]any{
		"primary": int32(2), "shadow": int32(9),
	}
	assert.False(t, identity.matches(candidate, candidateMismatch, candidateCall))
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
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"a": base,
		"b": &different,
	}))

	different.Calls[0].Outputs[0].Values[0].Kind = "int"
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"a": base,
		"b": &different,
	}))
}

func TestComparisonRuntimeResultUsesCallExecutionState(t *testing.T) {
	output := []*runtimeOutputCapture{{ID: 1}}
	tests := []struct {
		name       string
		call       runtimeCallResult
		state      runtimeCallExecutionState
		errno      *int32
		wantReturn bool
		wantOutput bool
	}{
		{
			name: "not executed",
			call: runtimeCallResult{
				Error: 998, ReturnValue: int64Ptr(-1), Outputs: output,
			},
			state: callNotExecuted,
		},
		{
			name: "started but unfinished",
			call: runtimeCallResult{
				Flags: flatrpc.CallFlagExecuted, Error: 38,
				ReturnValue: int64Ptr(-1), Outputs: output,
			},
			state: callStarted,
		},
		{
			name: "finished with error",
			call: runtimeCallResult{
				Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				Error: 22, ReturnValue: int64Ptr(-1), Outputs: output,
			},
			state: callFinishedError,
			errno: int32Ptr(22),
		},
		{
			name: "finished successfully",
			call: runtimeCallResult{
				Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				ReturnValue: int64Ptr(7), Outputs: output,
			},
			state:      callFinishedOK,
			wantReturn: true,
			wantOutput: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := comparisonRuntimeResultFor(&runtimeResult{
				Status: queue.Success,
				Calls:  []runtimeCallResult{test.call},
			})
			require.Len(t, result.Calls, 1)
			call := result.Calls[0]
			assert.Equal(t, test.state, call.State)
			assert.Equal(t, test.errno, call.Error)
			assert.Equal(t, test.wantReturn, call.ReturnValue != nil)
			assert.Equal(t, test.wantOutput, call.Outputs != nil)
		})
	}
}

func TestCompareRuntimeResultsIgnoresBlockedFlag(t *testing.T) {
	base := &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{{
			Name:        "read",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
		}},
	}
	blocked := *base
	blocked.Calls = append([]runtimeCallResult(nil), base.Calls...)
	blocked.Calls[0].Flags |= flatrpc.CallFlagBlocked

	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"a": base,
		"b": &blocked,
	}))
}

func TestRuntimeResultCompletionRecognizesMissingCallSentinels(t *testing.T) {
	for _, test := range []struct {
		errno int32
		text  string
	}{{998, "executor did not emit"}, {999, "runner did not receive"}} {
		result := &runtimeResult{Status: queue.Success, Calls: []runtimeCallResult{{
			Index: 0, Name: "read", Error: test.errno,
		}}}
		completion := runtimeResultCompletionFor(result)
		assert.True(t, completion.partial)
		assert.Equal(t, 0, completion.prefix)
		assert.Contains(t, completion.description, test.text)
	}
}

func TestCompareRuntimeResultsTreatsIncompleteSuffixAsInconclusive(t *testing.T) {
	complete := &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{
			{Index: 0, Name: "read", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, ReturnValue: int64Ptr(0)},
			{Index: 1, Name: "write", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, ReturnValue: int64Ptr(0)},
		},
	}
	partial := *complete
	partial.Calls = append([]runtimeCallResult(nil), complete.Calls...)
	partial.Calls[1] = runtimeCallResult{Index: 1, Name: "write", Error: 998}

	analysis := compareRuntimeResults(map[string]*runtimeResult{
		"v6.1": complete,
		"v6.2": &partial,
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeInconclusive, analysis.Outcome)
	require.Len(t, analysis.Compared["v6.1"].Calls, 1)
	require.Len(t, analysis.Compared["v6.2"].Calls, 1)
	assert.Contains(t, analysis.PartialSamples["v6.2"][0], "executor did not emit")
}

func TestCompareRuntimeResultsKeepsStablePrefixBeforeIncompleteSuffix(t *testing.T) {
	result := func(errno int32, incomplete bool) *runtimeResult {
		second := runtimeCallResult{
			Index: 1, Name: "write", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
		}
		if incomplete {
			second = runtimeCallResult{Index: 1, Name: "write", Error: 998}
		}
		return &runtimeResult{Status: queue.Success, Calls: []runtimeCallResult{
			{Index: 0, Name: "read", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, Error: errno, ReturnValue: int64Ptr(-1)},
			second,
		}}
	}
	analysis := compareRuntimeResults(map[string]*runtimeResult{
		"v6.1": result(12, true),
		"v6.2": result(13, false),
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
	require.Len(t, analysis.Compared["v6.1"].Calls, 1)
	assert.Equal(t, int32(12), *analysis.Compared["v6.1"].Calls[0].Error)
	assert.Equal(t, int32(13), *analysis.Compared["v6.2"].Calls[0].Error)
	assert.NotEmpty(t, analysis.PartialSamples["v6.1"])
}

func TestCompareRuntimeSamplesTreatsPartialOnlyAsInconclusive(t *testing.T) {
	sample := func() *runtimeResult {
		return &runtimeResult{Status: queue.Success, Calls: []runtimeCallResult{
			{Index: 0, Name: "read", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, ReturnValue: int64Ptr(0)},
			{Index: 1, Name: "write", Error: 998},
		}}
	}
	analysis := compareRuntimeSamples(map[string][]*runtimeResult{
		"v6.1": {sample(), sample(), sample()},
		"v6.2": {sample(), sample(), sample()},
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeInconclusive, analysis.Outcome)
	assert.Empty(t, analysis.StableDifferences)
	assert.NotEmpty(t, analysis.PartialSamples["v6.1"])
	require.Len(t, analysis.Compared["v6.1"].Calls, 1)
}

func TestCompareRuntimeSamplesKeepsStablePrefixBeforePartialSuffix(t *testing.T) {
	sample := func(errno int32, incomplete bool) *runtimeResult {
		second := runtimeCallResult{Index: 1, Name: "write", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, ReturnValue: int64Ptr(0)}
		if incomplete {
			second = runtimeCallResult{Index: 1, Name: "write", Error: 998}
		}
		return &runtimeResult{Status: queue.Success, Calls: []runtimeCallResult{
			{Index: 0, Name: "read", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, Error: errno, ReturnValue: int64Ptr(-1)},
			second,
		}}
	}
	analysis := compareRuntimeSamples(map[string][]*runtimeResult{
		"v6.1": {sample(12, true), sample(12, true), sample(12, true)},
		"v6.2": {sample(13, false), sample(13, false), sample(13, false)},
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
	require.NotEmpty(t, analysis.StableDifferences)
	assert.Equal(t, "errno", analysis.StableDifferences[0].Kind)
	assert.NotEmpty(t, analysis.PartialSamples["v6.1"])
}

func TestCompareRuntimeResultsKeepsSuccessFailureDifference(t *testing.T) {
	success := &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{{
			Name:        "mremap",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
		}},
	}
	failure := *success
	failure.Calls = append([]runtimeCallResult(nil), success.Calls...)
	failure.Calls[0].Error = 12

	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"v6.1": &failure,
		"v6.2": success,
	}))
}

func TestCompareRuntimeResultsKeepsProgramStatusDifference(t *testing.T) {
	for _, status := range []queue.Status{queue.Crashed, queue.Hanged} {
		t.Run(status.String(), func(t *testing.T) {
			assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
				"a": {Status: queue.Success},
				"b": {Status: status},
			}))
		})
	}
}

func TestCompareRuntimeResultsTreatsMissingResultAsInconclusive(t *testing.T) {
	analysis := compareRuntimeResults(map[string]*runtimeResult{
		"a": nil,
		"b": {Status: queue.Success},
	})

	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeInconclusive, analysis.Outcome)
}

func TestCompareRuntimeSamplesRejectsInvalidSamples(t *testing.T) {
	valid := &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{{
			Name:        "read",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
		}},
	}
	tests := []struct {
		name   string
		mutate func(*runtimeResult)
	}{
		{
			name: "fault injected",
			mutate: func(result *runtimeResult) {
				result.Calls[0].Flags |= flatrpc.CallFlagFaultInjected
			},
		},
		{
			name: "fault injected crash",
			mutate: func(result *runtimeResult) {
				result.Status = queue.Crashed
				result.Calls[0].Flags |= flatrpc.CallFlagFaultInjected
			},
		},
		{
			name: "missing successful return",
			mutate: func(result *runtimeResult) {
				result.Calls[0].ReturnValue = nil
			},
		},
		{
			name: "missing successful output capture",
			mutate: func(result *runtimeResult) {
				result.Calls[0].Outputs = []*runtimeOutputCapture{{Missing: true}}
			},
		},
		{
			name: "faulted successful output capture",
			mutate: func(result *runtimeResult) {
				result.Calls[0].Outputs = []*runtimeOutputCapture{{Faulted: true}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := *valid
			invalid.Calls = append([]runtimeCallResult(nil), valid.Calls...)
			test.mutate(&invalid)
			analysis := compareRuntimeSamples(map[string][]*runtimeResult{
				"v6.1": {valid, &invalid, valid},
				"v6.2": {valid, valid, valid},
			})
			require.NotNil(t, analysis)
			assert.Equal(t, comparisonOutcomeInconclusive, analysis.Outcome)
			assert.NotEmpty(t, analysis.InvalidSamples["v6.1"])
		})
	}
}

func TestCompareRuntimeSamplesDoesNotMaskStableStatusDifference(t *testing.T) {
	crashed := func(flags flatrpc.CallFlag) *runtimeResult {
		return &runtimeResult{
			Status: queue.Crashed,
			Calls:  []runtimeCallResult{{Name: "read", Flags: flags}},
		}
	}
	success := &runtimeResult{Status: queue.Success}
	analysis := compareRuntimeSamples(map[string][]*runtimeResult{
		"crashing": {
			crashed(0),
			crashed(flatrpc.CallFlagExecuted),
			crashed(flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished),
		},
		"working": {success, success, success},
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
	require.Len(t, analysis.StableDifferences, 1)
	assert.Equal(t, "status", analysis.StableDifferences[0].Kind)
}

func TestCompareRuntimeSamplesDoesNotMaskStableCallStateDifference(t *testing.T) {
	result := func(firstErrno int32, secondReturn int64) *runtimeResult {
		return &runtimeResult{
			Status: queue.Success,
			Calls: []runtimeCallResult{
				{
					Index: 0, Name: "mremap",
					Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
					Error: firstErrno, ReturnValue: int64Ptr(0),
				},
				{
					Index: 1, Name: "open",
					Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
					ReturnValue: int64Ptr(secondReturn),
				},
			},
		}
	}
	analysis := compareRuntimeSamples(map[string][]*runtimeResult{
		"v6.1": {result(12, 3), result(12, 4), result(12, 5)},
		"v6.2": {result(0, 6), result(0, 7), result(0, 8)},
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
	assert.Contains(t, analysis.UnstableFields["v6.1"], "calls[1].return_value")
	assert.Contains(t, analysis.UnstableFields["v6.2"], "calls[1].return_value")
	require.NotEmpty(t, analysis.StableDifferences)
	assert.Equal(t, "call_state", analysis.StableDifferences[0].Kind)
}

func TestCompareRuntimeSamplesSavesOnlyInstabilityAsInconclusive(t *testing.T) {
	result := func(errno int32) *runtimeResult {
		return &runtimeResult{
			Status: queue.Success,
			Calls: []runtimeCallResult{{
				Name:  "ptrace",
				Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				Error: errno,
			}},
		}
	}
	analysis := compareRuntimeSamples(map[string][]*runtimeResult{
		"v6.1": {result(1), result(2), result(3)},
		"v6.2": {result(1), result(1), result(1)},
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeInconclusive, analysis.Outcome)
	assert.Empty(t, analysis.StableDifferences)
	assert.Contains(t, analysis.UnstableFields["v6.1"], "calls[0].error")
}

func TestCompareRuntimeSamplesReportsStableLeafDifferences(t *testing.T) {
	result := func(errno int32, ret int64, output uint64) *runtimeResult {
		call := runtimeCallResult{
			Name:        "read",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			Error:       errno,
			ReturnValue: int64Ptr(ret),
		}
		if errno == 0 {
			call.Outputs = []*runtimeOutputCapture{{
				ID: 0,
				Values: []*runtimeDecodedOutput{{
					Path: "arg[1].value", Kind: "int", Value: uint64Ptr(output),
				}},
			}}
		}
		return &runtimeResult{Status: queue.Success, Calls: []runtimeCallResult{call}}
	}
	tests := []struct {
		name  string
		left  *runtimeResult
		right *runtimeResult
		kind  string
	}{
		{name: "errno", left: result(1, -1, 0), right: result(2, -1, 0), kind: "errno"},
		{name: "return", left: result(0, 1, 7), right: result(0, 2, 7), kind: "return_value"},
		{name: "output", left: result(0, 1, 7), right: result(0, 1, 8), kind: "output"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analysis := compareRuntimeSamples(map[string][]*runtimeResult{
				"a": {test.left, test.left, test.left},
				"b": {test.right, test.right, test.right},
			})

			require.NotNil(t, analysis)
			assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
			require.Len(t, analysis.StableDifferences, 1)
			assert.Equal(t, test.kind, analysis.StableDifferences[0].Kind)
		})
	}

	stable := result(0, 1, 7)
	assert.Nil(t, compareRuntimeSamples(map[string][]*runtimeResult{
		"a": {stable, stable, stable},
		"b": {stable, stable, stable},
	}))
}

func TestCompareRuntimeSamplesKeepsStableOutputAlongsideUnstableOutput(t *testing.T) {
	result := func(stable, unstable uint64) *runtimeResult {
		return &runtimeResult{
			Status: queue.Success,
			Calls: []runtimeCallResult{{
				Name:        "read",
				Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				ReturnValue: int64Ptr(0),
				Outputs: []*runtimeOutputCapture{{
					ID: 0,
					Values: []*runtimeDecodedOutput{
						{Path: "arg[1].stable", Kind: "int", Value: uint64Ptr(stable)},
						{Path: "arg[1].unstable", Kind: "int", Value: uint64Ptr(unstable)},
					},
				}},
			}},
		}
	}
	analysis := compareRuntimeSamples(map[string][]*runtimeResult{
		"a": {result(7, 1), result(7, 2), result(7, 3)},
		"b": {result(8, 4), result(8, 5), result(8, 6)},
	})

	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
	require.Len(t, analysis.StableDifferences, 1)
	assert.Equal(t, "calls[0].outputs.arg[1].stable", analysis.StableDifferences[0].Path)
	assert.Contains(t, analysis.UnstableFields["a"], "calls[0].outputs.arg[1].unstable")
	assert.Contains(t, analysis.UnstableFields["b"], "calls[0].outputs.arg[1].unstable")
}

func BenchmarkCompareRuntimeSamplesOutputs(b *testing.B) {
	for _, leaves := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("leaves_%d", leaves), func(b *testing.B) {
			result := runtimeResultWithOutputLeaves(leaves)
			samples := map[string][]*runtimeResult{
				"a": {result, result, result},
				"b": {result, result, result},
			}
			b.ResetTimer()
			for range b.N {
				compareRuntimeSamples(samples)
			}
		})
	}
}

func runtimeResultWithOutputLeaves(leaves int) *runtimeResult {
	values := make([]*runtimeDecodedOutput, leaves)
	for i := range values {
		values[i] = &runtimeDecodedOutput{
			Path:  fmt.Sprintf("arg[0].value[%d]", i),
			Kind:  "int",
			Value: uint64Ptr(uint64(i)),
		}
	}
	return &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{{
			Name:        "test",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
			Outputs:     []*runtimeOutputCapture{{ID: 0, Values: values}},
		}},
	}
}

func TestCompareRuntimeResultsNormalizesResourceReturns(t *testing.T) {
	result := func(value int64, resource bool) *runtimeResult {
		return &runtimeResult{
			Status: queue.Success,
			Calls: []runtimeCallResult{{
				Name:             "open",
				Flags:            flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				ReturnValue:      int64Ptr(value),
				ReturnType:       "fd",
				ReturnIsResource: resource,
			}},
		}
	}
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"a": result(3, true),
		"b": result(11, true),
	}))
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"a": result(3, false),
		"b": result(11, false),
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

func TestDecodeOutputArgSkipsPadding(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	var padding prog.Type
	prog.ForeachType(target.Syscalls, func(typ prog.Type, _ *prog.TypeCtx) {
		if padding == nil && prog.IsPad(typ) {
			padding = typ
		}
	})
	require.NotNil(t, padding)
	arg := padding.DefaultArg(prog.DirOut)
	assert.Empty(t, decodeOutputArg(target, arg, "arg[0].pad", make([]byte, arg.Size())))
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
func TestOutputPoliciesCanonicalizeWithoutDiscardingRawValues(t *testing.T) {
	target := &prog.Target{
		PtrSize: 8, DataOffset: 0x100000, NumPages: 4, PageSize: 4096,
	}
	identity := prog.OutputPolicy{Kind: prog.OutputPolicyResourceIdentity, Domain: "fd"}
	left := runtimeResultWithPolicy(target, identity, 11)
	right := runtimeResultWithPolicy(target, identity, 27)
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{"left": left, "right": right}))
	require.NotNil(t, left.Calls[0].Outputs[0].Values[0].Value)
	assert.Equal(t, uint64(11), *left.Calls[0].Outputs[0].Values[0].Value)
	require.NotNil(t, left.Calls[0].Outputs[0].Values[0].CanonicalValue)

	sameIdentity := runtimeResultWithPolicy(target, identity, 11, 11)
	differentIdentities := runtimeResultWithPolicy(target, identity, 27, 28)
	analysis := compareRuntimeResults(map[string]*runtimeResult{
		"same": sameIdentity, "different": differentIdentities,
	})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)

	semantic := prog.OutputPolicy{Kind: prog.OutputPolicySemantic}
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left":  runtimeResultWithPolicy(target, semantic, 1),
		"right": runtimeResultWithPolicy(target, semantic, 2),
	}))
}

func TestLinuxStatOutputPoliciesReachRuntimeDecoder(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	p := mustDeserializeProg(t, target,
		`fstat(0xffffffffffffffff, &(0x7f0000000000))`)
	plan := p.OutputCapturePlan(0)
	require.Len(t, plan, 1)
	data := make([]byte, plan[0].Size)
	binary.LittleEndian.PutUint64(data[0:], 17)
	binary.LittleEndian.PutUint64(data[8:], 1234)

	res := testResult(0, "")
	res.Info.Calls[0].ReturnValue = 0
	res.Info.Calls[0].ReturnValueValid = true
	res.Info.Calls[0].Outputs = []*flatrpc.OutputCapture{{Id: plan[0].ID, Data: data}}
	result := summarizeRuntimeResult("v6.2", &queue.Request{
		Prog:     p,
		ExecOpts: flatrpc.ExecOpts{ExecFlags: flatrpc.ExecFlagCollectOutputs},
	}, res)

	require.Len(t, result.Calls[0].Outputs, 1)
	outputs := result.Calls[0].Outputs[0].Values
	var device, inode *runtimeDecodedOutput
	for _, output := range outputs {
		switch output.Path {
		case "arg[1].st_dev":
			device = output
		case "arg[1].st_ino":
			inode = output
		}
	}
	require.NotNil(t, device)
	require.NotNil(t, inode)
	assert.Equal(t, prog.OutputPolicyFilesystemIdentity, device.OutputPolicy.Kind)
	assert.Equal(t, "mount", device.OutputPolicy.Domain)
	assert.Equal(t, prog.OutputPolicyObjectIdentity, inode.OutputPolicy.Kind)
	require.NotNil(t, device.CanonicalValue)
	require.NotNil(t, inode.CanonicalValue)
	assert.Equal(t, uint64(17), *device.Value, "raw value must remain available")
}

func TestTimestampPolicyIsIgnoredByDefault(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	p := mustDeserializeProg(t, target,
		`clock_gettime(0x0, &(0x7f0000000000))`)
	plan := p.OutputCapturePlan(0)
	require.Len(t, plan, 1)

	makeResult := func(sec, nsec uint64) *runtimeResult {
		data := make([]byte, plan[0].Size)
		binary.LittleEndian.PutUint64(data[0:], sec)
		binary.LittleEndian.PutUint64(data[8:], nsec)
		res := testResult(0, "")
		res.Info.Calls[0].ReturnValue = 0
		res.Info.Calls[0].ReturnValueValid = true
		res.Info.Calls[0].Outputs = []*flatrpc.OutputCapture{{Id: plan[0].ID, Data: data}}
		return summarizeRuntimeResult("test", &queue.Request{
			Prog:     p,
			ExecOpts: flatrpc.ExecOpts{ExecFlags: flatrpc.ExecFlagCollectOutputs},
		}, res)
	}

	zeroSeconds := makeResult(0, 200)
	oneSecond := makeResult(1, 200)
	zeroSec := zeroSeconds.Calls[0].Outputs[0].Values[0]
	oneSec := oneSecond.Calls[0].Outputs[0].Values[0]
	require.True(t, zeroSec.IdentitySpecial)
	require.False(t, oneSec.IdentitySpecial)
	assert.Nil(t, zeroSec.CanonicalValue)
	assert.Nil(t, oneSec.CanonicalValue)

	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"zero-seconds": zeroSeconds,
		"one-second":   oneSecond,
	}))
	assert.True(t, zeroSec.IdentitySpecial, "raw result metadata must remain available")
}

func TestOutputPoliciesReservedCounterAndTimestamp(t *testing.T) {
	target := &prog.Target{PtrSize: 8}
	reserved := prog.OutputPolicy{Kind: prog.OutputPolicyReserved}
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left":  runtimeResultWithPolicy(target, reserved, 1),
		"right": runtimeResultWithPolicy(target, reserved, 2),
	}))

	counter := prog.OutputPolicy{Kind: prog.OutputPolicyCounter}
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left":  runtimeResultWithPolicy(target, counter, 11),
		"right": runtimeResultWithPolicy(target, counter, 99),
	}))
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"zero": runtimeResultWithPolicy(target, counter, 0),
		"set":  runtimeResultWithPolicy(target, counter, 99),
	}))

	timestamp := prog.OutputPolicy{
		Kind: prog.OutputPolicyTimestamp, Domain: "filesystem",
	}
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"old": runtimeResultWithPolicy(target, timestamp, 100, 200),
		"new": runtimeResultWithPolicy(target, timestamp, 200, 300),
	}))
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"valid":   runtimeResultWithPolicy(target, timestamp, 100, 200),
		"invalid": runtimeResultWithPolicy(target, timestamp, 100, 1_000_000_000),
	}))

	exactTimestamp := timestamp
	exactTimestamp.Mode = "exact"
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left":  runtimeResultWithPolicy(target, exactTimestamp, 100, 200),
		"right": runtimeResultWithPolicy(target, exactTimestamp, 100, 200),
	}))
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left":  runtimeResultWithPolicy(target, exactTimestamp, 100, 200),
		"right": runtimeResultWithPolicy(target, exactTimestamp, 100, 201),
	}))
}

func TestOutputPolicyNormalizesRelativeAddresses(t *testing.T) {
	policy := prog.OutputPolicy{Kind: prog.OutputPolicyAddress, Domain: "user_memory"}
	leftTarget := &prog.Target{
		PtrSize: 8, DataOffset: 0x100000, NumPages: 1, PageSize: 4096,
	}
	rightTarget := &prog.Target{
		PtrSize: 8, DataOffset: 0x200000, NumPages: 1, PageSize: 4096,
	}
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left":  runtimeResultWithPolicy(leftTarget, policy, 0x100020),
		"right": runtimeResultWithPolicy(rightTarget, policy, 0x200020),
	}))
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left":  runtimeResultWithPolicy(leftTarget, policy, 0x100020),
		"right": runtimeResultWithPolicy(rightTarget, policy, 0x200028),
	}))
	unknownLeft := runtimeResultWithPolicy(leftTarget, policy, 0x5000)
	unknownRight := runtimeResultWithPolicy(rightTarget, policy, 0x6000)
	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left": unknownLeft, "right": unknownRight,
	}))
	assert.Equal(t, "address is outside known program regions",
		unknownLeft.Calls[0].Outputs[0].Values[0].NormalizationErr)
}

func TestVersionIdentityPolicyClassifiesStableDifference(t *testing.T) {
	target := &prog.Target{PtrSize: 8}
	policy := prog.OutputPolicy{Kind: prog.OutputPolicyVersionIdentity}
	analysis := compareRuntimeResults(map[string]*runtimeResult{
		"old": runtimeResultWithPolicy(target, policy, 1),
		"new": runtimeResultWithPolicy(target, policy, 2),
	})
	require.NotNil(t, analysis)
	require.Len(t, analysis.StableDifferences, 1)
	difference := analysis.StableDifferences[0]
	assert.Equal(t, string(prog.OutputPolicyVersionIdentity), difference.OutputPolicy)
	assert.Equal(t, string(runtimeDiffExpectedVersion), difference.TriageLabel)
	assert.Equal(t, "output_policy", difference.TriageLabelID)
}

func runtimeResultWithPolicy(target *prog.Target, policy prog.OutputPolicy,
	values ...uint64) *runtimeResult {
	paths := make([]string, len(values))
	for index := range paths {
		paths[index] = fmt.Sprintf("arg[0].value[%d]", index)
	}
	return runtimeResultWithNamedPolicy(target, policy, paths, values)
}

func runtimeResultWithNamedPolicy(target *prog.Target, policy prog.OutputPolicy,
	paths []string, values []uint64) *runtimeResult {
	outputs := make([]*runtimeDecodedOutput, len(values))
	for index, value := range values {
		outputs[index] = &runtimeDecodedOutput{
			Path: paths[index], Type: "int64", Kind: "int", Value: uint64Ptr(value),
			OutputPolicy: policy, PolicySource: "test",
		}
	}
	result := &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{{
			Name: "test", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
			Outputs:     []*runtimeOutputCapture{{ID: 0, Values: outputs}},
		}},
	}
	normalizeRuntimeOutputs(&prog.Prog{Target: target}, result)
	return result
}
