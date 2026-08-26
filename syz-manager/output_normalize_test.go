// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
)

func TestTimestampExactNormalizesEachComponent(t *testing.T) {
	policy := prog.OutputPolicy{
		Kind: prog.OutputPolicyTimestamp, Domain: "clock", Mode: "exact",
	}
	values := []*runtimeDecodedOutput{
		{Path: "arg[0].sec", Type: "int64", Kind: "int", Value: uint64Ptr(0), OutputPolicy: policy},
		{Path: "arg[0].nsec", Type: "int64", Kind: "int", Value: uint64Ptr(123), OutputPolicy: policy},
	}
	result := &runtimeResult{
		Status: queue.Success,
		Calls: []runtimeCallResult{{
			Name: "test", Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
			Outputs:     []*runtimeOutputCapture{{ID: 0, Values: values}},
		}},
	}

	normalizeRuntimeOutputs(&prog.Prog{Target: &prog.Target{PtrSize: 8}}, result)

	assert.Equal(t, &runtimeCanonicalOutput{
		Kind: string(prog.OutputPolicyTimestamp), State: "exact", Exact: uint64Ptr(0),
	}, values[0].CanonicalValue)
	assert.Equal(t, &runtimeCanonicalOutput{
		Kind: string(prog.OutputPolicyTimestamp), State: "exact", Exact: uint64Ptr(123),
	}, values[1].CanonicalValue)
}
