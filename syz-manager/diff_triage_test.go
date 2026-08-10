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

func TestRuntimeDiffFingerprintUsesActualArguments(t *testing.T) {
	makeResult := func(option uint64, version string) *runtimeResult {
		return &runtimeResult{
			Runtime:        version,
			RuntimeVersion: version,
			Status:         queue.Success,
			Calls: []runtimeCallResult{{
				Index: 0,
				Name:  "prctl$PR_SET_THP_DISABLE",
				Args: []*runtimeCallArg{{
					Name: "option", Type: "int", Kind: "const", Value: uint64Ptr(option),
				}},
				Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				Error: 22,
			}},
		}
	}
	makeDifference := func(samples map[string][]*runtimeResult) runtimeFieldDifference {
		difference := runtimeFieldDifference{
			Kind:      "errno",
			Path:      "calls[0].error",
			CallIndex: intPtr(0),
			CallName:  "prctl$PR_SET_THP_DISABLE",
			Values:    map[string]any{"left": int32(22), "right": int32(0)},
		}
		differences := []runtimeFieldDifference{difference}
		annotateRuntimeDifferences(differences, samples, nil)
		return differences[0]
	}

	left := map[string][]*runtimeResult{
		"left":  {makeResult(65, "6.1")},
		"right": {makeResult(65, "6.4")},
	}
	right := map[string][]*runtimeResult{
		"left":  {makeResult(65, "6.1")},
		"right": {makeResult(65, "6.4")},
	}
	leftDifference := makeDifference(left)
	rightDifference := makeDifference(right)
	assert.Equal(t, leftDifference.Signature, rightDifference.Signature,
		"kernel identity and observed errno are not part of the semantic signature")
	assert.Equal(t, leftDifference.Fingerprint, rightDifference.Fingerprint,
		"the exact fingerprint is stable when only runtime versions differ")

	changed := makeResult(66, "6.4")
	left["right"][0] = changed
	changedDifference := runtimeFieldDifference{
		Kind: "errno", Path: "calls[0].error", CallIndex: intPtr(0),
		CallName: "prctl$PR_SET_THP_DISABLE",
		Values:   map[string]any{"left": int32(22), "right": int32(0)},
	}
	annotateRuntimeDifferences([]runtimeFieldDifference{changedDifference}, left, nil)
	assert.NotEqual(t, leftDifference.Signature, changedDifference.Signature,
		"actual syscall arguments must distinguish stale/mixed syscall names")
	assert.NotEqual(t, leftDifference.Fingerprint, changedDifference.Fingerprint)
}

func TestRuntimeDiffLabelsMatchFingerprintAndScope(t *testing.T) {
	samples := map[string][]*runtimeResult{
		"old": {{Runtime: "old", RuntimeVersion: "6.1"}},
		"new": {{Runtime: "new", RuntimeVersion: "6.4"}},
	}
	difference := runtimeFieldDifference{
		Kind: "return_value", Path: "calls[2].return_value", CallIndex: intPtr(2),
		CallName: "rseq", Values: map[string]any{"old": int64(-1), "new": int64(0)},
	}
	differences := []runtimeFieldDifference{difference}
	annotateRuntimeDifferences(differences, samples, nil)
	difference = differences[0]
	require.NotEmpty(t, difference.Signature)
	require.NotEmpty(t, difference.Fingerprint)

	path := filepath.Join(t.TempDir(), "labels.json")
	data, err := json.Marshal(runtimeDiffLabelFile{
		FormatVersion: 1,
		Labels: []runtimeDiffLabelEntry{{
			ID: "rseq-v6.3", Label: runtimeDiffExpectedVersion,
			Signature: difference.Signature,
			Scope: runtimeDiffLabelScope{
				RuntimeNames:    []string{"new", "old"},
				RuntimeVersions: map[string]string{"old": "6.1", "new": "6.4"},
			},
			Note: "reviewed UAPI evolution",
		}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	store, err := loadRuntimeDiffLabels(path)
	require.NoError(t, err)

	annotated := difference
	annotatedDifferences := []runtimeFieldDifference{annotated}
	annotateRuntimeDifferences(annotatedDifferences, samples, store)
	annotated = annotatedDifferences[0]
	assert.Equal(t, string(runtimeDiffExpectedVersion), annotated.TriageLabel)
	assert.Equal(t, "rseq-v6.3", annotated.TriageLabelID)
	assert.Equal(t, "reviewed UAPI evolution", annotated.TriageNote)

	wrongScope := map[string][]*runtimeResult{
		"old": {{Runtime: "old", RuntimeVersion: "6.1"}},
		"new": {{Runtime: "new", RuntimeVersion: "6.5"}},
	}
	unmatched := difference
	unmatchedDifferences := []runtimeFieldDifference{unmatched}
	annotateRuntimeDifferences(unmatchedDifferences, wrongScope, store)
	unmatched = unmatchedDifferences[0]
	assert.Empty(t, unmatched.TriageLabel)
}

func TestCompareRuntimeSamplesRetainsAndAnnotatesStableDifferences(t *testing.T) {
	result := func(errno int32, version string) *runtimeResult {
		return &runtimeResult{
			Runtime: version, RuntimeVersion: version, Status: queue.Success,
			Calls: []runtimeCallResult{{
				Index: 0, Name: "rseq",
				Args:        []*runtimeCallArg{{Name: "len", Type: "int", Kind: "const", Value: uint64Ptr(115)}},
				Flags:       flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
				Error:       errno,
				ReturnValue: int64Ptr(0),
			}},
		}
	}
	samples := map[string][]*runtimeResult{
		"old": {result(22, "6.1"), result(22, "6.1")},
		"new": {result(38, "6.4"), result(38, "6.4")},
	}
	withoutFilter := compareRuntimeSamples(samples)
	require.NotNil(t, withoutFilter)
	require.Len(t, withoutFilter.StableDifferences, 1)
	assert.Equal(t, "errno", withoutFilter.StableDifferences[0].Kind)
	assert.NotEmpty(t, withoutFilter.StableDifferences[0].Fingerprint)
	assert.Equal(t, withoutFilter.StableDifferences[0].Fingerprint, withoutFilter.Triage.FirstFingerprint)

	labels := &runtimeDiffLabelStore{labels: []runtimeDiffLabelEntry{{
		ID: "manual-rseq", Label: runtimeDiffUnknown,
		Fingerprint: withoutFilter.StableDifferences[0].Fingerprint,
	}}}
	withLabel := compareRuntimeSamples(samples, labels)
	require.NotNil(t, withLabel)
	require.Len(t, withLabel.StableDifferences, 1)
	assert.Equal(t, string(runtimeDiffUnknown), withLabel.StableDifferences[0].TriageLabel)
	assert.Equal(t, 1, withLabel.Triage.LabelCounts[string(runtimeDiffUnknown)])
}

func TestConfigureRuntimeDiffLabelsResolvesWorkdirPaths(t *testing.T) {
	workdir := t.TempDir()
	coord := newMultiRuntimeCoordinator(workdir)
	require.NoError(t, coord.configureRuntimeDiffLabels(""))
	require.NotNil(t, coord.diffLabels)
	assert.Empty(t, coord.diffLabels.labels)

	labelPath := filepath.Join(workdir, "review.json")
	data, err := json.Marshal(runtimeDiffLabelFile{
		FormatVersion: 1,
		Labels: []runtimeDiffLabelEntry{{
			ID: "review", Label: runtimeDiffKernelBug, Signature: "signature",
		}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(labelPath, data, 0o644))
	require.NoError(t, coord.configureRuntimeDiffLabels("review.json"))
	require.Len(t, coord.diffLabels.labels, 1)
	assert.Equal(t, "review", coord.diffLabels.labels[0].ID)
}

func TestLoadRuntimeDiffLabelsRejectsInvalidEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.json")
	data, err := json.Marshal(runtimeDiffLabelFile{
		FormatVersion: 1,
		Labels:        []runtimeDiffLabelEntry{{ID: "bad", Label: runtimeDiffLabel("not-a-label")}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, err = loadRuntimeDiffLabels(path)
	assert.Error(t, err)

	missing, err := loadRuntimeDiffLabels(filepath.Join(t.TempDir(), "missing.json"))
	require.NoError(t, err)
	assert.Empty(t, missing.labels)
}
