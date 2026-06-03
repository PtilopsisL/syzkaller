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
				"tag": "linux-v6.2"
			},
			{
				"name": "v6.1",
				"kernel_obj": "/linux-v6.1",
				"tag": "linux-v6.1"
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
	assert.Equal(t, "dash", primary.DashboardClient)

	assert.Equal(t, "multi-manager/v6.1", shadow.Name)
	assert.Equal(t, filepath.Join(cfg.Workdir, "runtimes", "v6.1"), shadow.Workdir)
	assert.False(t, shadow.Cover)
	assert.Equal(t, ":0", shadow.RPC)
	assert.Empty(t, shadow.DashboardClient)
	assert.Empty(t, shadow.HubClient)
	assert.Equal(t, "/linux-v6.1", shadow.KernelObj)
}

func TestLoadDataRejectsMultiRuntimeSnapshot(t *testing.T) {
	_, err := LoadData([]byte(fmt.Sprintf(`{
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
		"runtimes": [{"name": "main"}]
	}`, t.TempDir())))
	require.ErrorContains(t, err, "multi-runtime mode does not support snapshot")
}
