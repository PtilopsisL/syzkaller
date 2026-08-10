// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeOutputPolicyOverlay(t *testing.T) {
	file := runtimeOutputPolicyFile{
		FormatVersion: 1,
		Rules: []runtimeOutputPolicyRule{{
			ID: "stat-device",
			Selector: runtimeOutputPolicySelector{
				CaptureType: "stat", Field: "st_dev",
			},
			Policy: prog.OutputPolicy{
				Kind: prog.OutputPolicyFilesystemIdentity, Domain: "mount",
			},
		}},
	}
	data, err := json.Marshal(file)
	require.NoError(t, err)
	filePath := filepath.Join(t.TempDir(), "policies.json")
	require.NoError(t, os.WriteFile(filePath, data, 0o644))

	store, err := loadRuntimeOutputPolicies(filePath)
	require.NoError(t, err)
	assert.NotEmpty(t, store.hash)

	output := &runtimeDecodedOutput{
		Path: "arg[1].st_dev", Type: "intptr",
		OutputPolicy: prog.OutputPolicy{Kind: prog.OutputPolicySemantic},
	}
	captures := []*runtimeOutputCapture{{
		Type: "stat", Values: []*runtimeDecodedOutput{output},
	}}
	applyRuntimeOutputPolicies("fstat", captures, store)
	assert.Equal(t, prog.OutputPolicyFilesystemIdentity, output.OutputPolicy.Kind)
	assert.Equal(t, "mount", output.OutputPolicy.Domain)
	assert.Equal(t, "external:stat-device", output.PolicySource)
}

func TestRuntimeOutputPolicyOverlayValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		file runtimeOutputPolicyFile
	}{
		{
			name: "unknown policy",
			file: runtimeOutputPolicyFile{Rules: []runtimeOutputPolicyRule{{
				ID: "bad", Selector: runtimeOutputPolicySelector{Field: "value"},
				Policy: prog.OutputPolicy{Kind: prog.OutputPolicyKind("unknown")},
			}}},
		},
		{
			name: "empty selector",
			file: runtimeOutputPolicyFile{Rules: []runtimeOutputPolicyRule{{
				ID: "bad", Policy: prog.OutputPolicy{Kind: prog.OutputPolicySemantic},
			}}},
		},
		{
			name: "duplicate selector",
			file: runtimeOutputPolicyFile{Rules: []runtimeOutputPolicyRule{
				{
					ID: "one", Selector: runtimeOutputPolicySelector{Field: "value"},
					Policy: prog.OutputPolicy{Kind: prog.OutputPolicySemantic},
				},
				{
					ID: "two", Selector: runtimeOutputPolicySelector{Field: "value"},
					Policy: prog.OutputPolicy{Kind: prog.OutputPolicyCounter},
				},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.file)
			require.NoError(t, err)
			filePath := filepath.Join(t.TempDir(), "policies.json")
			require.NoError(t, os.WriteFile(filePath, data, 0o644))
			_, err = loadRuntimeOutputPolicies(filePath)
			assert.Error(t, err)
		})
	}
}

func TestConfigureRuntimeOutputPoliciesResolvesWorkdirPath(t *testing.T) {
	workdir := t.TempDir()
	file := runtimeOutputPolicyFile{
		FormatVersion: 1,
		Rules: []runtimeOutputPolicyRule{{
			ID: "counter", Selector: runtimeOutputPolicySelector{Field: "runtime"},
			Policy: prog.OutputPolicy{Kind: prog.OutputPolicyCounter},
		}},
	}
	data, err := json.Marshal(file)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "policies.json"), data, 0o644))

	coord := newMultiRuntimeCoordinator(workdir)
	require.NoError(t, coord.configureRuntimeOutputPolicies("policies.json"))
	require.NotNil(t, coord.outputPolicies)
	require.Len(t, coord.outputPolicies.rules, 1)
	assert.NotEmpty(t, coord.outputPolicies.hash)
}
