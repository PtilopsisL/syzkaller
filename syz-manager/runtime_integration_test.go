// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testManagerRuntimeVM = "test-manager-runtime"

var registerTestManagerRuntimeVM sync.Once

func TestInitRuntimeCreatesKernelRuntime(t *testing.T) {
	cfg := testManagerConfig(t)
	mgr := &Manager{
		cfg:  cfg,
		mode: ModeFuzzing,
	}

	require.NoError(t, mgr.initRuntime(false))
	t.Cleanup(func() {
		require.NoError(t, mgr.runtime.Close())
	})

	require.NotNil(t, mgr.runtime)
	require.NotNil(t, mgr.runtime.Server())
	require.NotNil(t, mgr.runtime.Pool())
	require.NotNil(t, mgr.primary)
	assert.NotZero(t, dispatcherDefaultJobPtr(t, mgr.runtime.Pool()))
}

func TestInitRuntimeCreatesPrimaryAndShadowRuntimes(t *testing.T) {
	primaryCfg := testManagerConfig(t)
	shadowCfg := testManagerConfig(t)
	shadowCfg.Workdir = t.TempDir()
	shadowCfg.Cover = false

	displayCfg := testManagerConfig(t)
	displayCfg.PrimaryRuntime = "primary"
	displayCfg.Runtimes = []mgrconfig.Runtime{
		{Name: "primary"},
		{Name: "shadow"},
	}
	displayCfg.RuntimeConfigs = map[string]*mgrconfig.Config{
		"primary": primaryCfg,
		"shadow":  shadowCfg,
	}

	mgr := &Manager{
		cfg:        primaryCfg,
		displayCfg: displayCfg,
		mode:       ModeFuzzing,
	}

	require.NoError(t, mgr.initRuntime(false))
	t.Cleanup(func() {
		require.NoError(t, mgr.closeRuntimes())
	})

	require.NotNil(t, mgr.primary)
	require.NotNil(t, mgr.runtime)
	require.NotNil(t, mgr.programRegistry)
	require.Len(t, mgr.shadows, 1)
	require.Len(t, mgr.allRuntimes, 2)
	assert.Equal(t, mgr.primary.runtime, mgr.runtime)
	assert.Equal(t, "primary", mgr.primary.name)
	assert.Equal(t, "shadow", mgr.shadows["shadow"].name)
	assert.Equal(t, "primary", mgr.primary.crashStore.Namespace)
	assert.Equal(t, "shadow", mgr.shadows["shadow"].crashStore.Namespace)
}

func TestInitRuntimeUsesPrimaryNamedStatsInMultiRuntimeMode(t *testing.T) {
	primaryName := "primary-stats"
	shadowName := "shadow-stats"
	primaryCfg := testManagerConfig(t)
	shadowCfg := testManagerConfig(t)
	shadowCfg.Workdir = t.TempDir()
	shadowCfg.Cover = false

	displayCfg := testManagerConfig(t)
	displayCfg.PrimaryRuntime = primaryName
	displayCfg.Runtimes = []mgrconfig.Runtime{
		{Name: primaryName},
		{Name: shadowName},
	}
	displayCfg.RuntimeConfigs = map[string]*mgrconfig.Config{
		primaryName: primaryCfg,
		shadowName:  shadowCfg,
	}

	mgr := &Manager{
		cfg:        primaryCfg,
		displayCfg: displayCfg,
		mode:       ModeFuzzing,
	}

	require.NoError(t, mgr.initRuntime(false))
	t.Cleanup(func() {
		require.NoError(t, mgr.closeRuntimes())
	})

	mgr.servStats.StatExecs.Add(7)

	statsByName := map[string]int{}
	for _, item := range stat.Collect(stat.Console) {
		statsByName[item.Name] = item.V
	}
	assert.Equal(t, 7, statsByName["exec total ["+primaryName+"]"])
	assert.Zero(t, statsByName["exec total ["+shadowName+"]"])
}

func testManagerConfig(t *testing.T) *mgrconfig.Config {
	t.Helper()
	registerTestManagerRuntimeVM.Do(func() {
		vmimpl.Register(testManagerRuntimeVM, vmimpl.Type{
			Ctor: func(env *vmimpl.Env) (vmimpl.Pool, error) {
				return &testManagerRuntimePool{}, nil
			},
		})
	})

	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	sysTarget := targets.Get(targets.Linux, targets.AMD64)

	return &mgrconfig.Config{
		Name:    "manager-runtime-test",
		Workdir: t.TempDir(),
		RPC:     ":0",
		Type:    testManagerRuntimeVM,
		Sandbox: "none",
		Procs:   1,
		Cover:   false,
		SSHUser: "root",
		Derived: mgrconfig.Derived{
			Target:       target,
			SysTarget:    sysTarget,
			TargetOS:     targets.Linux,
			TargetArch:   targets.AMD64,
			TargetVMArch: targets.AMD64,
			ExecutorBin:  "/bin/true",
			Timeouts:     sysTarget.Timeouts(1),
		},
	}
}

func dispatcherDefaultJobPtr(t *testing.T, pool *vm.Dispatcher) uintptr {
	t.Helper()
	field := reflect.ValueOf(pool).Elem().FieldByName("defaultJob")
	require.True(t, field.IsValid())
	return field.Pointer()
}

type testManagerRuntimePool struct{}

func (pool *testManagerRuntimePool) Count() int {
	return 1
}

func (pool *testManagerRuntimePool) Create(_ context.Context, _ string, index int) (vmimpl.Instance, error) {
	return &testManagerRuntimeInstance{index: index}, nil
}

type testManagerRuntimeInstance struct {
	index int
}

func (inst *testManagerRuntimeInstance) Copy(hostSrc string) (string, error) {
	return hostSrc, nil
}

func (inst *testManagerRuntimeInstance) Forward(port int) (string, error) {
	return fmt.Sprintf("localhost:%d", port), nil
}

func (inst *testManagerRuntimeInstance) Run(context.Context, string) (<-chan vmimpl.Chunk, <-chan error, error) {
	outc := make(chan vmimpl.Chunk)
	errc := make(chan error, 1)
	close(outc)
	errc <- nil
	return outc, errc, nil
}

func (inst *testManagerRuntimeInstance) Diagnose(*report.Report) ([]byte, bool) {
	return nil, false
}

func (inst *testManagerRuntimeInstance) Close() error {
	return nil
}
