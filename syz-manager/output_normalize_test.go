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

func TestTimestampScopesDoNotCrossCalls(t *testing.T) {
	policy := prog.OutputPolicy{
		Kind: prog.OutputPolicyTimestamp, Domain: "clock", Scope: "observed",
	}
	makeResult := func(values ...uint64) *runtimeResult {
		calls := make([]runtimeCallResult, len(values))
		for index, value := range values {
			calls[index] = runtimeCallResult{
				Name:        "test",
				Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				ReturnValue: int64Ptr(0),
				Outputs: []*runtimeOutputCapture{{
					ID: uint32(index),
					Values: []*runtimeDecodedOutput{{
						Path: "arg[0].sec", Type: "int64", Kind: "int",
						Value: uint64Ptr(value), OutputPolicy: policy,
						PolicyScope: "arg[0]#observed",
					}},
				}},
			}
		}
		result := &runtimeResult{Status: queue.Success, Calls: calls}
		normalizeRuntimeOutputs(&prog.Prog{Target: &prog.Target{PtrSize: 8}}, result)
		return result
	}

	assert.NotNil(t, compareRuntimeResults(map[string]*runtimeResult{
		"left": makeResult(0, 1), "right": makeResult(1, 0),
	}))
}
