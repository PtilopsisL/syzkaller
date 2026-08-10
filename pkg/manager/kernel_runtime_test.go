// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"context"
	"fmt"
	mathrand "math/rand"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKernelRuntimeVM = "test-kernel-runtime"

var registerTestKernelRuntimeVM sync.Once

func TestNewKernelRuntimeSuccess(t *testing.T) {
	cfg := testKernelRuntimeConfig(t, testKernelRuntimeVM)

	runtime, err := NewKernelRuntime("test", cfg, KernelRuntimeOptions{})
	require.NoError(t, err)
	assert.Equal(t, "test", runtime.Name())
	assert.Same(t, cfg, runtime.Config())
	assert.NotNil(t, runtime.Pool())
	assert.NotNil(t, runtime.Reporter())
	assert.NotNil(t, runtime.Crashes())
	assert.Zero(t, runtime.Features())
}

func TestNewKernelRuntimeWrapsVMPoolError(t *testing.T) {
	cfg := testKernelRuntimeConfig(t, "definitely-unknown-vm-type")

	runtime, err := NewKernelRuntime("broken", cfg, KernelRuntimeOptions{})
	require.Nil(t, runtime)
	require.Error(t, err)
	assert.ErrorContains(t, err, `failed to create vm.Pool for "broken"`)
	assert.ErrorContains(t, err, "unknown instance type")
}

func TestNewKernelRuntimeVMLess(t *testing.T) {
	cfg := testKernelRuntimeConfig(t, "none")
	cfg.Derived.VMLess = true

	runtime, err := NewKernelRuntime("vmless", cfg, KernelRuntimeOptions{})
	require.NoError(t, err)
	assert.NotNil(t, runtime.Server())
	assert.Nil(t, runtime.Pool())
}

func TestNewKernelRuntimeUsesCustomInstanceHandler(t *testing.T) {
	cfg := testKernelRuntimeConfig(t, testKernelRuntimeVM)
	handler := func(context.Context, *vm.Instance, dispatcher.UpdateInfo) {}

	runtime, err := NewKernelRuntime("custom-handler", cfg, KernelRuntimeOptions{
		InstanceHandler: handler,
	})
	require.NoError(t, err)
	assert.Equal(t, reflect.ValueOf(handler).Pointer(), dispatcherDefaultJobPtr(t, runtime.Pool()))
}

func TestKernelRuntimeMachineCheckedUsesProvidedSource(t *testing.T) {
	cfg := testKernelRuntimeConfig(t, testKernelRuntimeVM)
	req := &queue.Request{Prog: testKernelRuntimeProg(cfg.Target)}
	source := &singleSource{req: req}
	dup := &countingExecutor{}

	runtime, err := NewKernelRuntime("provided-source", cfg, KernelRuntimeOptions{
		Source:        source,
		DuplicateInto: dup,
	})
	require.NoError(t, err)

	next, err := runtime.machineCheckedSource(0, testKernelRuntimeSyscalls(cfg.Target))
	require.NoError(t, err)
	assert.Same(t, req, next.Next())
	assert.Zero(t, dup.count.Load())
}

func TestKernelRuntimeMachineCheckedDuplicatesWhenConfigured(t *testing.T) {
	cfg := testKernelRuntimeConfig(t, testKernelRuntimeVM)
	dup := &countingExecutor{}
	seedCh := make(chan []fuzzer.Candidate, 1)
	seedCh <- []fuzzer.Candidate{{Prog: testKernelRuntimeProg(cfg.Target)}}

	runtime, err := NewKernelRuntime("tee-source", cfg, KernelRuntimeOptions{
		Candidates:    seedCh,
		DuplicateInto: dup,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runtime.ctx = ctx

	next, err := runtime.machineCheckedSource(0, testKernelRuntimeSyscalls(cfg.Target))
	require.NoError(t, err)
	req := next.Next()
	require.NotNil(t, req)
	require.EqualValues(t, 1, dup.count.Load())
	require.NotNil(t, dup.last)
	assert.NotSame(t, req, dup.last)
	assert.Equal(t, string(req.Prog.Serialize()), string(dup.last.Prog.Serialize()))
}

func TestKernelRuntimeTriageProgress(t *testing.T) {
	cfg := testKernelRuntimeConfig(t, testKernelRuntimeVM)
	seedCh := make(chan []fuzzer.Candidate, 1)
	seedCh <- []fuzzer.Candidate{}

	runtime, err := NewKernelRuntime("triage", cfg, KernelRuntimeOptions{
		Candidates: seedCh,
	})
	require.NoError(t, err)
	assert.Equal(t, 0.0, runtime.TriageProgress())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runtime.ctx = ctx

	_, err = runtime.machineCheckedSource(0, testKernelRuntimeSyscalls(cfg.Target))
	require.NoError(t, err)
	assert.Equal(t, 1.0, runtime.TriageProgress())
}

func testKernelRuntimeConfig(t *testing.T, vmType string) *mgrconfig.Config {
	t.Helper()
	registerTestKernelRuntimeVM.Do(func() {
		vmimpl.Register(testKernelRuntimeVM, vmimpl.Type{
			Ctor: func(env *vmimpl.Env) (vmimpl.Pool, error) {
				return &testKernelRuntimePool{}, nil
			},
		})
	})

	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	sysTarget := targets.Get(targets.Linux, targets.AMD64)

	return &mgrconfig.Config{
		Name:    "kernel-runtime-test",
		Workdir: t.TempDir(),
		RPC:     ":0",
		Type:    vmType,
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

func testKernelRuntimeSyscalls(target *prog.Target) map[*prog.Syscall]bool {
	ret := make(map[*prog.Syscall]bool)
	for _, call := range target.Syscalls {
		ret[call] = true
	}
	return ret
}

func testKernelRuntimeProg(target *prog.Target) *prog.Prog {
	return target.Generate(mathrand.NewSource(0), 1, target.DefaultChoiceTable())
}

func dispatcherDefaultJobPtr(t *testing.T, pool *vm.Dispatcher) uintptr {
	t.Helper()
	field := reflect.ValueOf(pool).Elem().FieldByName("defaultJob")
	require.True(t, field.IsValid())
	return field.Pointer()
}

type singleSource struct {
	req *queue.Request
}

func (src *singleSource) Next() *queue.Request {
	ret := src.req
	src.req = nil
	return ret
}

type countingExecutor struct {
	count atomic.Int64
	last  *queue.Request
}

func (exec *countingExecutor) Submit(req *queue.Request) {
	exec.count.Add(1)
	exec.last = req
}

type testKernelRuntimePool struct{}

func (pool *testKernelRuntimePool) Count() int {
	return 1
}

func (pool *testKernelRuntimePool) Create(_ context.Context, _ string, index int) (vmimpl.Instance, error) {
	return &testKernelRuntimeInstance{index: index}, nil
}

type testKernelRuntimeInstance struct {
	index int
}

func (inst *testKernelRuntimeInstance) Copy(hostSrc string) (string, error) {
	return hostSrc, nil
}

func (inst *testKernelRuntimeInstance) Forward(port int) (string, error) {
	return fmt.Sprintf("localhost:%d", port), nil
}

func (inst *testKernelRuntimeInstance) Run(context.Context, string) (<-chan vmimpl.Chunk, <-chan error, error) {
	outc := make(chan vmimpl.Chunk)
	errc := make(chan error, 1)
	close(outc)
	errc <- nil
	return outc, errc, nil
}

func (inst *testKernelRuntimeInstance) Diagnose(*report.Report) ([]byte, bool) {
	return nil, false
}

func (inst *testKernelRuntimeInstance) Close() error {
	return nil
}
