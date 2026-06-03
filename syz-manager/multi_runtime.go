// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

type managedRuntime struct {
	name       string
	cfg        *mgrconfig.Config
	runtime    *manager.KernelRuntime
	controller *runtimeController
	crashStore *manager.CrashStore
	reproLoop  *manager.ReproLoop
	features   flatrpc.Feature
	shadow     bool
}

type runtimeController struct {
	mgr  *Manager
	slot *managedRuntime
}

func (ctrl *runtimeController) MaxSignal() signal.Signal {
	if ctrl.slot.shadow {
		return nil
	}
	return ctrl.mgr.MaxSignal()
}

func (ctrl *runtimeController) BugFrames() ([]string, []string) {
	return ctrl.mgr.BugFrames()
}

func (ctrl *runtimeController) MachineChecked(features flatrpc.Feature,
	syscalls map[*prog.Syscall]bool) (queue.Source, error) {
	return ctrl.mgr.machineChecked(ctrl.slot, features, syscalls)
}

func (ctrl *runtimeController) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	if ctrl.slot.shadow {
		return nil, nil
	}
	return ctrl.mgr.CoverageFilter(modules)
}

type runtimeReproView struct {
	mgr  *Manager
	slot *managedRuntime
}

func (view *runtimeReproView) RunRepro(ctx context.Context, crash *manager.Crash) *manager.ReproResult {
	return view.mgr.runReproOn(view.slot, ctx, crash)
}

func (view *runtimeReproView) NeedRepro(crash *manager.Crash) bool {
	return view.mgr.needReproOn(view.slot, crash)
}

func (view *runtimeReproView) ResizeReproPool(size int) {
	if pool := view.slot.runtime.Pool(); pool != nil {
		pool.ReserveForRun(size)
	}
}

type storedProgram struct {
	ID        int64
	ProgData  []byte
	Important bool
}

type shadowProgramRegistry struct {
	nextID atomic.Int64

	mu        sync.Mutex
	consumers map[string]*shadowConsumer
	statuses  map[string]map[int64]queue.Status
}

type shadowConsumer struct {
	target       *prog.Target
	enabledCalls map[int]bool

	mu     sync.Mutex
	cond   *sync.Cond
	queue  []storedProgram
	closed bool
}

func newShadowProgramRegistry() *shadowProgramRegistry {
	return &shadowProgramRegistry{
		consumers: map[string]*shadowConsumer{},
		statuses:  map[string]map[int64]queue.Status{},
	}
}

func newShadowConsumer(target *prog.Target, enabledSyscalls map[*prog.Syscall]bool) *shadowConsumer {
	enabled := make(map[int]bool, len(enabledSyscalls))
	for call := range enabledSyscalls {
		enabled[call.ID] = true
	}
	consumer := &shadowConsumer{
		target:       target,
		enabledCalls: enabled,
	}
	consumer.cond = sync.NewCond(&consumer.mu)
	return consumer
}

func (registry *shadowProgramRegistry) EnsureRuntime(name string, target *prog.Target,
	enabledSyscalls map[*prog.Syscall]bool) queue.Source {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, ok := registry.consumers[name]; ok {
		panic(fmt.Sprintf("shadow runtime %q registered twice", name))
	}
	registry.statuses[name] = map[int64]queue.Status{}
	consumer := newShadowConsumer(target, enabledSyscalls)
	registry.consumers[name] = consumer
	return &shadowProgramSource{
		registry: registry,
		name:     name,
		consumer: consumer,
		target:   target,
	}
}

func (registry *shadowProgramRegistry) Close() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, consumer := range registry.consumers {
		consumer.close()
	}
}

func (registry *shadowProgramRegistry) registerPrimary(runtimeName string, req *queue.Request) {
	if req == nil || req.Prog == nil {
		return
	}
	if req.ProgID == 0 {
		req.ProgID = registry.nextID.Add(1)
	}
	registry.mu.Lock()
	if registry.statuses[runtimeName] == nil {
		registry.statuses[runtimeName] = map[int64]queue.Status{}
	}
	consumers := make([]*shadowConsumer, 0, len(registry.consumers))
	for _, consumer := range registry.consumers {
		consumers = append(consumers, consumer)
	}
	registry.mu.Unlock()

	program := storedProgram{
		ID:        req.ProgID,
		ProgData:  req.Prog.Serialize(),
		Important: req.Important,
	}
	for _, consumer := range consumers {
		consumer.enqueue(program)
	}
	req.OnDone(func(r *queue.Request, res *queue.Result) bool {
		registry.record(runtimeName, r.ProgID, res.Status)
		return true
	})
}

func (registry *shadowProgramRegistry) record(runtimeName string, progID int64, status queue.Status) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.statuses[runtimeName] == nil {
		registry.statuses[runtimeName] = map[int64]queue.Status{}
	}
	registry.statuses[runtimeName][progID] = status
}

func (registry *shadowProgramRegistry) status(runtimeName string, progID int64) (queue.Status, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	statuses := registry.statuses[runtimeName]
	if statuses == nil {
		return 0, false
	}
	status, ok := statuses[progID]
	return status, ok
}

type shadowProgramSource struct {
	registry *shadowProgramRegistry
	name     string
	consumer *shadowConsumer
	target   *prog.Target
}

func (source *shadowProgramSource) Next() *queue.Request {
	for {
		item, ok := source.consumer.next()
		if !ok {
			return nil
		}
		program, err := source.target.Deserialize(item.ProgData, prog.NonStrict)
		if err != nil {
			log.Logf(0, "shadow runtime %q failed to deserialize program %d: %v",
				source.name, item.ID, err)
			source.registry.record(source.name, item.ID, queue.ExecFailure)
			continue
		}
		if !source.consumer.supports(program) {
			source.registry.record(source.name, item.ID, queue.Unsupported)
			continue
		}
		req := &queue.Request{
			ProgID:    item.ID,
			Prog:      program,
			Important: item.Important,
		}
		fuzzer.EnableSyscallTrace(req)
		req.OnDone(func(r *queue.Request, res *queue.Result) bool {
			source.registry.record(source.name, r.ProgID, res.Status)
			return true
		})
		return req
	}
}

func (consumer *shadowConsumer) enqueue(program storedProgram) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.closed {
		return
	}
	consumer.queue = append(consumer.queue, program)
	consumer.cond.Signal()
}

func (consumer *shadowConsumer) next() (storedProgram, bool) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	for len(consumer.queue) == 0 && !consumer.closed {
		consumer.cond.Wait()
	}
	if len(consumer.queue) == 0 {
		return storedProgram{}, false
	}
	item := consumer.queue[0]
	consumer.queue = consumer.queue[1:]
	return item, true
}

func (consumer *shadowConsumer) close() {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	consumer.closed = true
	consumer.cond.Broadcast()
}

func (consumer *shadowConsumer) supports(program *prog.Prog) bool {
	for _, call := range program.Calls {
		if !consumer.enabledCalls[call.Meta.ID] {
			return false
		}
	}
	return true
}

func (mgr *Manager) makeInstanceHandler(slot *managedRuntime) func(context.Context, *vm.Instance, dispatcher.UpdateInfo) {
	return func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
		mgr.fuzzerInstanceFor(slot, ctx, inst, updInfo)
	}
}

func (mgr *Manager) makeController(slot *managedRuntime) rpcserver.Manager {
	return &runtimeController{
		mgr:  mgr,
		slot: slot,
	}
}

func (mgr *Manager) runtimeList() []*managedRuntime {
	if mgr.primary == nil {
		return nil
	}
	if !mgr.displayCfg.IsMultiRuntime() {
		return []*managedRuntime{mgr.primary}
	}
	ret := make([]*managedRuntime, 0, len(mgr.allRuntimes))
	for _, runtime := range mgr.displayCfg.Runtimes {
		ret = append(ret, mgr.allRuntimes[runtime.Name])
	}
	return ret
}

func (mgr *Manager) closeRuntimes() error {
	var firstErr error
	for _, slot := range mgr.runtimeList() {
		if err := slot.runtime.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if mgr.programRegistry != nil {
		mgr.programRegistry.Close()
	}
	return firstErr
}

func (mgr *Manager) togglePauseAll(paused bool) {
	for _, slot := range mgr.runtimeList() {
		if pool := slot.runtime.Pool(); pool != nil {
			pool.TogglePause(paused)
		}
	}
}

func newManagedCrashStore(baseDir string, cfg *mgrconfig.Config, runtimeName string, namespaced bool) *manager.CrashStore {
	store := manager.NewCrashStore(cfg)
	store.BaseDir = baseDir
	store.Runtime = runtimeName
	if namespaced {
		store.Namespace = runtimeName
	}
	return store
}
