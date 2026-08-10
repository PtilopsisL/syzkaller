// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig_test

import (
	"fmt"
	"path/filepath"
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
