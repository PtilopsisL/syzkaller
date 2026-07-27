// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		text string
		want kernelVersion
		ok   bool
	}{
		{text: "v6.4", want: kernelVersion{Major: 6, Minor: 4}, ok: true},
		{text: "6.4.0-custom", want: kernelVersion{Major: 6, Minor: 4}, ok: true},
		{text: "Linux version 6.4.0", want: kernelVersion{Major: 6, Minor: 4}, ok: true},
		{text: "unknown", ok: false},
		{text: "6", ok: false},
	}
	for _, test := range tests {
		t.Run(test.text, func(t *testing.T) {
			got, ok := parseKernelVersion(test.text)
			assert.Equal(t, test.ok, ok)
			if test.ok {
				assert.Equal(t, test.want, got)
			}
		})
	}
}

func TestFilterExpectedVersionDifferencesAdditiveBits(t *testing.T) {
	difference := runtimeFieldDifference{
		Kind:      "output",
		Path:      "calls[3].outputs.arg[1].features",
		CallIndex: intPtr(3),
		CallName:  "io_uring_setup",
		Values: map[string]any{
			"old": runtimeDecodedOutput{Type: "int32", Dir: "out", Kind: "int", Size: 4, Value: uint64Ptr(8191)},
			"new": runtimeDecodedOutput{Type: "int32", Dir: "out", Kind: "int", Size: 4, Value: uint64Ptr(16383)},
		},
	}
	samples := map[string][]*runtimeResult{
		"old": {{Runtime: "old", RuntimeVersion: "v6.1"}},
		"new": {{Runtime: "new", RuntimeVersion: "v6.4"}},
	}
	unexpected, expected := filterExpectedVersionDifferences(
		[]runtimeFieldDifference{difference}, samples, defaultVersionCompatibilityRules)
	assert.Empty(t, unexpected)
	require.Len(t, expected, 1)
	assert.Equal(t, "io_uring.params.features.additive-v6.4", expected[0].Rule)
	assert.Equal(t, difference, expected[0].Difference)
}

func TestFilterExpectedVersionDifferencesFailsClosed(t *testing.T) {
	base := runtimeFieldDifference{
		Kind: "output", Path: "calls[0].outputs.arg[1].features", CallName: "io_uring_setup",
		Values: map[string]any{
			"old": runtimeDecodedOutput{Type: "int32", Dir: "out", Kind: "int", Size: 4, Value: uint64Ptr(8191)},
			"new": runtimeDecodedOutput{Type: "int32", Dir: "out", Kind: "int", Size: 4, Value: uint64Ptr(16383)},
		},
	}
	tests := []struct {
		name    string
		mutate  func(*runtimeFieldDifference, map[string][]*runtimeResult)
		wantLen int
	}{
		{
			name: "unknown bit",
			mutate: func(difference *runtimeFieldDifference, _ map[string][]*runtimeResult) {
				difference.Values["new"] = runtimeDecodedOutput{Type: "int32", Dir: "out", Kind: "int", Size: 4, Value: uint64Ptr(8191 | 1<<14)}
			},
			wantLen: 1,
		},
		{
			name: "unknown version",
			mutate: func(_ *runtimeFieldDifference, samples map[string][]*runtimeResult) {
				samples["new"][0].RuntimeVersion = "future"
			},
			wantLen: 1,
		},
		{
			name: "wrong call",
			mutate: func(difference *runtimeFieldDifference, _ map[string][]*runtimeResult) {
				difference.CallName = "mmap"
			},
			wantLen: 1,
		},
		{
			name: "wrong output metadata",
			mutate: func(difference *runtimeFieldDifference, _ map[string][]*runtimeResult) {
				difference.Values["new"] = runtimeDecodedOutput{Type: "uint64", Dir: "out", Kind: "int", Size: 8, Value: uint64Ptr(16383)}
			},
			wantLen: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			difference := base
			difference.Values = map[string]any{}
			for name, value := range base.Values {
				difference.Values[name] = value
			}
			samples := map[string][]*runtimeResult{
				"old": {{Runtime: "old", RuntimeVersion: "v6.1"}},
				"new": {{Runtime: "new", RuntimeVersion: "v6.4"}},
			}
			test.mutate(&difference, samples)
			unexpected, expected := filterExpectedVersionDifferences(
				[]runtimeFieldDifference{difference}, samples, defaultVersionCompatibilityRules)
			assert.Len(t, unexpected, test.wantLen)
			assert.Empty(t, expected)
		})
	}
}

func TestMultiRuntimeCoordinatorAttachesRuntimeVersion(t *testing.T) {
	coord := newShadowProgramRegistry()
	coord.setRuntimeVersion("runtime", "6.4.0")
	result := &runtimeResult{Runtime: "runtime", Status: queue.Success}
	coord.recordRuntimeResult("runtime", 1, result)
	assert.Equal(t, "6.4.0", result.RuntimeVersion)
}

func TestCompareRuntimeResultsFiltersExpectedVersionDifference(t *testing.T) {
	old := versionedIoUringResult("old", "v6.1", 8191, 0)
	new := versionedIoUringResult("new", "v6.4", 16383, 0)
	assert.Nil(t, compareRuntimeResults(map[string]*runtimeResult{"old": old, "new": new}))

	new = versionedIoUringResult("new", "v6.4", 8191|1<<14, 0)
	analysis := compareRuntimeResults(map[string]*runtimeResult{"old": old, "new": new})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
	require.Len(t, analysis.StableDifferences, 1)
	assert.Equal(t, "output", analysis.StableDifferences[0].Kind)
	assert.Empty(t, analysis.ExpectedVersionDifferences)
}

func TestCompareRuntimeResultsKeepsUnknownAlongsideExpectedDifference(t *testing.T) {
	old := versionedIoUringResult("old", "v6.1", 8191, 1)
	new := versionedIoUringResult("new", "v6.4", 16383, 2)
	analysis := compareRuntimeResults(map[string]*runtimeResult{"old": old, "new": new})
	require.NotNil(t, analysis)
	assert.Equal(t, comparisonOutcomeMismatch, analysis.Outcome)
	require.Len(t, analysis.StableDifferences, 1)
	assert.Equal(t, "return_value", analysis.StableDifferences[0].Kind)
	require.Len(t, analysis.ExpectedVersionDifferences, 1)
	assert.Equal(t, "io_uring.params.features.additive-v6.4", analysis.ExpectedVersionDifferences[0].Rule)
}

func versionedIoUringResult(runtimeName, version string, features uint64, returnValue int64) *runtimeResult {
	return &runtimeResult{
		Runtime:        runtimeName,
		RuntimeVersion: version,
		Status:         queue.Success,
		Calls: []runtimeCallResult{{
			Index:       0,
			Name:        "io_uring_setup",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(0),
			Outputs: []*runtimeOutputCapture{{
				ID: 0,
				Values: []*runtimeDecodedOutput{{
					Path:  "arg[1].features",
					Type:  "int32",
					Dir:   "out",
					Kind:  "int",
					Size:  4,
					Value: uint64Ptr(features),
				}},
			}},
		}, {
			Index:       1,
			Name:        "read",
			Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
			ReturnValue: int64Ptr(returnValue),
		}},
	}
}
