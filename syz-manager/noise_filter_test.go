// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLearnNoiseRulesAndDenoise(t *testing.T) {
	first := noiseTestRuntimeResult("v6.1", 1, 10, 3, 4)
	second := noiseTestRuntimeResult("v6.1", 2, 11, 5, 4)
	rules := learnNoiseRules(map[string][]*runtimeResult{
		"v6.1": {first, second},
	})

	rule, ok := rules.Syscalls["pipe2"]
	require.True(t, ok)
	assert.True(t, rule.Ignore.Errno)
	assert.True(t, rule.Ignore.ReturnValue)
	assert.Equal(t, []string{"arg[0].rfd"}, rule.Ignore.Outputs)

	otherRuntime := noiseTestRuntimeResult("v6.2", 9, 99, 7, 4)
	assert.Nil(t, compareRuntimeResultsWithRules(map[string]*runtimeResult{
		"v6.1": first,
		"v6.2": otherRuntime,
	}, rules))

	otherRuntime.Calls[0].Outputs[0].Values[1].Value = uint64Ptr(8)
	assert.NotNil(t, compareRuntimeResultsWithRules(map[string]*runtimeResult{
		"v6.1": first,
		"v6.2": otherRuntime,
	}, rules))
}

func TestNoiseFilterPersistsAndReloadsRules(t *testing.T) {
	workdir := t.TempDir()
	filter := newNoiseFilter(workdir)
	changed, err := filter.learn(map[string][]*runtimeResult{
		"v6.1": {
			noiseTestRuntimeResult("v6.1", 0, 0, 3, 4),
			noiseTestRuntimeResult("v6.1", 0, 0, 5, 4),
		},
	})
	require.NoError(t, err)
	require.True(t, changed)

	path := filepath.Join(workdir, noiseRuleFileName)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var stored noiseRuleFile
	require.NoError(t, json.Unmarshal(data, &stored))
	assert.Equal(t, noiseRuleVersion, stored.Version)
	assert.Equal(t, []string{"arg[0].rfd"},
		stored.Syscalls["pipe2"].Ignore.Outputs)

	reloaded := newNoiseFilter(workdir).snapshot()
	assert.Equal(t, stored, reloaded)
}

func noiseTestRuntimeResult(runtime string, errno int32, returnValue int64,
	readFD, writeFD uint64) *runtimeResult {
	return &runtimeResult{
		Runtime:    runtime,
		Status:     queue.Success,
		StatusName: queue.Success.String(),
		Calls: []runtimeCallResult{{
			Index:       0,
			Name:        "pipe2",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			Error:       errno,
			ReturnValue: int64Ptr(returnValue),
			Outputs: []*runtimeOutputCapture{{
				ID:           0,
				Path:         "arg[0]",
				Type:         "pipefd",
				Size:         8,
				CapturedSize: 8,
				Values: []*runtimeDecodedOutput{
					{
						Path:  "arg[0].rfd",
						Type:  "fd",
						Dir:   "out",
						Kind:  "result",
						Value: uint64Ptr(readFD),
					},
					{
						Path:  "arg[0].wfd",
						Type:  "fd",
						Dir:   "out",
						Kind:  "result",
						Value: uint64Ptr(writeFD),
					},
				},
			}},
		}},
	}
}
