// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDataMultiRuntime(t *testing.T) {
	workdir := t.TempDir()
	cfg, err := LoadData([]byte(fmt.Sprintf(`{
		"name": "multi-manager",
		"target": "linux/amd64",
		"http": "localhost:0",
		"workdir": %q,
		"kernel_obj": "/linux",
		"image": "./testdata/wheezy.img",
		"syzkaller": "./testdata/syzkaller",
		"type": "qemu",
		"cover": true,
		"dashboard_client": "dash",
		"dashboard_addr": "https://dashboard.example",
		"dashboard_key": "secret",
		"runtime_diff_labels": "labels.json",
		"runtime_output_policy": "output-policy.json",
		"vm": {
			"count": 2,
			"cpu": 1,
			"mem": 256,
			"kernel": "/linux/arch/x86/boot/bzImage"
		},
		"primary": "v6.2",
		"runtimes": [
			{
				"name": "v6.2",
				"tag": "linux-v6.2",
				"kernel_version": "6.2.0"
			},
			{
				"name": "v6.1",
				"kernel_obj": "/linux-v6.1",
				"tag": "linux-v6.1",
				"kernel_version": "v6.1.0"
			}
		]
	}`, workdir)))
	require.NoError(t, err)
	require.True(t, cfg.IsMultiRuntime())
	require.Len(t, cfg.RuntimeConfigs, 2)
	assert.Equal(t, DefaultMaxFirstRunInflight, cfg.MaxFirstRunInflight)
	assert.Equal(t, DefaultResumeFirstRunInflight, cfg.ResumeFirstRunInflight)

	primary := cfg.RuntimeConfigs["v6.2"]
	shadow := cfg.RuntimeConfigs["v6.1"]
	require.NotNil(t, primary)
	require.NotNil(t, shadow)

	assert.Equal(t, cfg.Name, primary.Name)
	assert.Equal(t, cfg.Workdir, primary.Workdir)
	assert.True(t, primary.Cover)
	assert.True(t, primary.CoverageLayout)
	assert.Equal(t, "dash", primary.DashboardClient)
	assert.Equal(t, "6.2.0", primary.KernelVersion)
	assert.Equal(t, "labels.json", cfg.RuntimeDiffLabels)
	assert.Equal(t, "labels.json", primary.RuntimeDiffLabels)
	assert.Equal(t, "output-policy.json", cfg.RuntimeOutputPolicy)
	assert.Equal(t, "output-policy.json", primary.RuntimeOutputPolicy)

	assert.Equal(t, "multi-manager/v6.1", shadow.Name)
	assert.Equal(t, filepath.Join(cfg.Workdir, "runtimes", "v6.1"), shadow.Workdir)
	assert.False(t, shadow.Cover)
	assert.True(t, shadow.CoverageLayout)
	assert.Equal(t, ":0", shadow.RPC)
	assert.Empty(t, shadow.DashboardClient)
	assert.Empty(t, shadow.HubClient)
	assert.Equal(t, "/linux-v6.1", shadow.KernelObj)
	assert.Equal(t, "v6.1.0", shadow.KernelVersion)
}

func TestLoadDataMultiRuntimeSnapshot(t *testing.T) {
	cfg, err := LoadData([]byte(fmt.Sprintf(`{
		"name": "multi-manager",
		"target": "linux/amd64",
		"http": "localhost:0",
		"workdir": %q,
		"kernel_obj": "/linux",
		"image": "./testdata/wheezy.img",
		"syzkaller": "./testdata/syzkaller",
		"type": "qemu",
		"snapshot": true,
		"vm": {
			"count": 1,
			"cpu": 1,
			"mem": 256,
			"kernel": "/linux/arch/x86/boot/bzImage"
		},
		"primary": "main",
		"runtimes": [
			{"name": "main"},
			{"name": "shadow", "kernel_obj": "/linux-shadow"}
		]
	}`, t.TempDir())))
	require.NoError(t, err)
	require.True(t, cfg.Snapshot)
	require.True(t, cfg.RuntimeConfigs["main"].Snapshot)
	require.True(t, cfg.RuntimeConfigs["shadow"].Snapshot)
	require.True(t, cfg.RuntimeConfigs["main"].CoverageLayout)
	require.True(t, cfg.RuntimeConfigs["shadow"].CoverageLayout)
}

func TestLoadDataMultiRuntimeComparisonPrimary(t *testing.T) {
	workdir := t.TempDir()
	data := fmt.Sprintf(`{
               "name": "multi-manager",
               "target": "linux/amd64",
               "http": "localhost:0",
               "workdir": %q,
               "kernel_obj": "/linux",
               "image": "./testdata/wheezy.img",
               "syzkaller": "./testdata/syzkaller",
               "type": "qemu",
               "cover": true,
               "snapshot": true,
               "vm": {
                       "count": 1,
                       "cpu": 1,
                       "mem": 256,
                       "kernel": "/linux/arch/x86/boot/bzImage"
               },
               "primary": "main",
               "comparison_primary": "main-comparison",
               "max_first_run_inflight": 10,
               "resume_first_run_inflight": 8,
               "runtimes": [
                       {"name": "main", "tag": "primary-tag", "kernel_version": "6.2.0"},
                       {"name": "shadow", "kernel_obj": "/linux-shadow"}
               ]
       }`, workdir)
	cfg, err := LoadData([]byte(data))
	require.NoError(t, err)
	require.Len(t, cfg.RuntimeConfigs, 3)
	require.Len(t, cfg.Runtimes, 3)
	assert.Equal(t, 10, cfg.MaxFirstRunInflight)
	assert.Equal(t, 8, cfg.ResumeFirstRunInflight)

	primary := cfg.RuntimeConfigs["main"]
	comparison := cfg.RuntimeConfigs["main-comparison"]
	shadow := cfg.RuntimeConfigs["shadow"]
	require.NotNil(t, primary)
	require.NotNil(t, comparison)
	require.NotNil(t, shadow)

	assert.False(t, primary.Snapshot)
	assert.True(t, primary.Cover)
	assert.True(t, primary.CoverageLayout)
	assert.Equal(t, workdir, primary.Workdir)

	assert.True(t, comparison.Snapshot)
	assert.False(t, comparison.Cover)
	assert.True(t, comparison.CoverageLayout)
	assert.Equal(t, filepath.Join(workdir, "runtimes", "main-comparison"), comparison.Workdir)
	assert.Equal(t, primary.KernelObj, comparison.KernelObj)
	assert.Equal(t, primary.Tag, comparison.Tag)
	assert.Equal(t, primary.KernelVersion, comparison.KernelVersion)

	assert.True(t, shadow.Snapshot)
	assert.Equal(t, "main-fuzzing", cfg.PrimaryFuzzingRuntimeName())

	for _, test := range []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{"snapshot required", `"snapshot": true`, `"snapshot": false`,
			"comparison_primary requires snapshot=true"},
		{"must differ from primary", `"comparison_primary": "main-comparison"`,
			`"comparison_primary": "main"`, "comparison_primary must differ from primary"},
		{"must not collide", `"comparison_primary": "main-comparison"`,
			`"comparison_primary": "shadow"`, "conflicts with a configured runtime"},
		{"fuzzing name must not collide", `"comparison_primary": "main-comparison"`,
			`"comparison_primary": "main-fuzzing"`, "fuzzing primary runtime name"},
		{"resume limit must be lower", `"resume_first_run_inflight": 8`,
			`"resume_first_run_inflight": 10`,
			"resume_first_run_inflight must be less than max_first_run_inflight"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadData([]byte(strings.Replace(data, test.old, test.new, 1)))
			require.ErrorContains(t, err, test.wantErr)
		})
	}

	var singleRuntime map[string]any
	require.NoError(t, json.Unmarshal([]byte(data), &singleRuntime))
	delete(singleRuntime, "primary")
	delete(singleRuntime, "runtimes")
	singleRuntimeData, err := json.Marshal(singleRuntime)
	require.NoError(t, err)
	_, err = LoadData(singleRuntimeData)
	require.ErrorContains(t, err, "comparison_primary requires multi-runtime mode")
}
