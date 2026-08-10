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
	stats      rpcserver.Stats
	shadow     bool
}

type runtimeController struct {
	mgr  *Manager
	slot *managedRuntime
}

func (ctrl *runtimeController) MaxSignal() signal.Signal {
	if ctrl.slot == nil || (!ctrl.slot.cfg.CoverageLayout && !ctrl.slot.cfg.Cover) {
		return nil
	}
	return ctrl.mgr.MaxSignal()
}

func (ctrl *runtimeController) BugFrames() ([]string, []string) {
	return ctrl.mgr.BugFrames()
}

func (ctrl *runtimeController) MachineChecked(features flatrpc.Feature,
	syscalls map[*prog.Syscall]bool) error {
	return ctrl.mgr.machineCheckedAndSetSource(ctrl.slot, features, syscalls)
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

type runStage int

const (
	runStageFuzz runStage = iota
	runStageRepro
)

const mismatchReproRuns = 3

type programRun struct {
	ID             int64
	ParentID       int64
	Stage          runStage
	Prog           *prog.Prog
	ProgData       []byte
	Important      bool
	Expected       map[string]bool
	Results        map[string]*runtimeResult
	Samples        map[string][]*runtimeResult
	ReproRuns      int
	InitialResults map[string]*runtimeResult
}

type multiRuntimeCoordinator struct {
	nextID atomic.Int64

	progIDMu       sync.Mutex
	progIDState    string
	reservedProgID int64

	mu              sync.Mutex
	consumers       map[string]*shadowConsumer
	reproQueues     map[string]*queue.PlainQueue
	runtimeVersions map[string]string
	statuses        map[string]map[int64]queue.Status
	runs            map[int64]*programRun
	store           *mismatchStore
	diffLabels      *runtimeDiffLabelStore
	outputPolicies  *runtimeOutputPolicyStore
}

type shadowConsumer struct {
	target       *prog.Target
	enabledCalls map[int]bool

	mu            sync.Mutex
	cond          *sync.Cond
	priorityQueue []*queue.Request
	queue         []storedProgram
	priorityBurst int
	closed        bool
}

func newMultiRuntimeCoordinator(workdir string) *multiRuntimeCoordinator {
	maxID := maxPersistedProgID(workdir)
	coord := &multiRuntimeCoordinator{
		progIDState:     progIDStatePath(workdir),
		reservedProgID:  maxID,
		consumers:       map[string]*shadowConsumer{},
		reproQueues:     map[string]*queue.PlainQueue{},
		runtimeVersions: map[string]string{},
		statuses:        map[string]map[int64]queue.Status{},
		runs:            map[int64]*programRun{},
		store:           newMismatchStore(workdir),
	}
	coord.nextID.Store(maxID)
	return coord
}

func (coord *multiRuntimeCoordinator) setRuntimeVersion(name, version string) {
	coord.mu.Lock()
	defer coord.mu.Unlock()
	if coord.runtimeVersions == nil {
		coord.runtimeVersions = make(map[string]string)
	}
	coord.runtimeVersions[name] = version
}

func newShadowProgramRegistry() *multiRuntimeCoordinator {
	return newMultiRuntimeCoordinator("")
}

func (coord *multiRuntimeCoordinator) allocateProgID() int64 {
	coord.progIDMu.Lock()
	defer coord.progIDMu.Unlock()

	id := coord.nextID.Load() + 1
	if id > coord.reservedProgID {
		reserved := id + progIDReserveBatch - 1
		if reserved < id {
			reserved = maxProgID
		}
		if err := saveProgIDState(coord.progIDState, reserved); err != nil {
			log.Logf(0, "failed to save runtime program ID state: %v", err)
		} else {
			coord.reservedProgID = reserved
		}
	}
	coord.nextID.Store(id)
	return id
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

func (coord *multiRuntimeCoordinator) EnsureRuntime(name string, target *prog.Target,
	enabledSyscalls map[*prog.Syscall]bool) queue.Source {
	coord.mu.Lock()
	defer coord.mu.Unlock()
	if _, ok := coord.consumers[name]; ok {
		panic(fmt.Sprintf("shadow runtime %q registered twice", name))
	}
	coord.statuses[name] = map[int64]queue.Status{}
	consumer := newShadowConsumer(target, enabledSyscalls)
	coord.consumers[name] = consumer
	source := &shadowProgramSource{
		coord:    coord,
		name:     name,
		consumer: consumer,
		target:   target,
	}
	return source
}

func (coord *multiRuntimeCoordinator) Close() {
	coord.mu.Lock()
	defer coord.mu.Unlock()
	for _, consumer := range coord.consumers {
		consumer.close()
	}
}

func (coord *multiRuntimeCoordinator) sourceForRuntime(name string, source queue.Source) queue.Source {
	coord.mu.Lock()
	defer coord.mu.Unlock()
	return queue.Order(coord.runtimeQueueLocked(name), source)
}

func (coord *multiRuntimeCoordinator) runtimeQueueLocked(name string) *queue.PlainQueue {
	if q := coord.reproQueues[name]; q != nil {
		return q
	}
	q := queue.Plain()
	coord.reproQueues[name] = q
	return q
}

func (coord *multiRuntimeCoordinator) registerPrimary(runtimeName string, req *queue.Request) {
	if req == nil || req.Prog == nil {
		return
	}
	if req.ProgID == 0 {
		req.ProgID = coord.allocateProgID()
	}
	coord.mu.Lock()
	if coord.statuses[runtimeName] == nil {
		coord.statuses[runtimeName] = map[int64]queue.Status{}
	}
	expected := map[string]bool{runtimeName: true}
	consumers := make(map[string]*shadowConsumer, len(coord.consumers))
	for name, consumer := range coord.consumers {
		expected[name] = true
		consumers[name] = consumer
	}
	coord.runs[req.ProgID] = &programRun{
		ID:        req.ProgID,
		Stage:     runStageFuzz,
		Prog:      req.Prog.Clone(),
		ProgData:  req.Prog.Serialize(),
		Important: req.Important,
		Expected:  expected,
		Results:   map[string]*runtimeResult{},
	}
	coord.mu.Unlock()

	program := storedProgram{
		ID:        req.ProgID,
		ProgData:  req.Prog.Serialize(),
		Important: req.Important,
	}
	for _, consumer := range consumers {
		consumer.enqueue(program)
	}
	req.OnDone(func(r *queue.Request, res *queue.Result) bool {
		coord.recordResult(runtimeName, r, res)
		return true
	})
}

func (coord *multiRuntimeCoordinator) recordStatus(runtimeName string, progID int64, status queue.Status) {
	coord.recordRuntimeResult(runtimeName, progID, &runtimeResult{
		Runtime:    runtimeName,
		Status:     status,
		StatusName: status.String(),
	})
}

func (coord *multiRuntimeCoordinator) recordResult(runtimeName string, req *queue.Request, res *queue.Result) {
	if req == nil || res == nil {
		return
	}
	coord.mu.Lock()
	policies := coord.outputPolicies
	coord.mu.Unlock()
	coord.recordRuntimeResult(runtimeName, req.ProgID,
		summarizeRuntimeResult(runtimeName, req, res, policies))
}

func (coord *multiRuntimeCoordinator) recordRuntimeResult(runtimeName string, progID int64,
	result *runtimeResult) {
	var completed *programRun
	var nextSample *programRun
	var nextQueue *queue.PlainQueue
	coord.mu.Lock()
	if result != nil && result.RuntimeVersion == "" {
		result.RuntimeVersion = coord.runtimeVersions[runtimeName]
	}
	if coord.statuses[runtimeName] == nil {
		coord.statuses[runtimeName] = map[int64]queue.Status{}
	}
	coord.statuses[runtimeName][progID] = result.Status
	run := coord.runs[progID]
	if run != nil && run.Expected[runtimeName] {
		switch run.Stage {
		case runStageFuzz:
			run.Results[runtimeName] = result
		case runStageRepro:
			if len(run.Samples[runtimeName]) < run.ReproRuns {
				run.Samples[runtimeName] = append(run.Samples[runtimeName], result)
			}
			if len(run.Samples[runtimeName]) < run.ReproRuns {
				nextSample = run
				nextQueue = coord.runtimeQueueLocked(runtimeName)
			}
		}
		if runComplete(run) {
			completed = run
			delete(coord.runs, progID)
		}
	}
	coord.mu.Unlock()
	if nextSample != nil {
		coord.submitReproSample(nextSample, runtimeName, nextQueue)
	}
	if completed != nil {
		coord.handleCompletedRun(completed)
	}
}

func runComplete(run *programRun) bool {
	switch run.Stage {
	case runStageFuzz:
		return len(run.Results) == len(run.Expected)
	case runStageRepro:
		for runtimeName := range run.Expected {
			if len(run.Samples[runtimeName]) != run.ReproRuns {
				return false
			}
		}
		return true
	default:
		panic(fmt.Sprintf("unknown multi-runtime run stage %d", run.Stage))
	}
}

func (coord *multiRuntimeCoordinator) status(runtimeName string, progID int64) (queue.Status, bool) {
	coord.mu.Lock()
	defer coord.mu.Unlock()
	statuses := coord.statuses[runtimeName]
	if statuses == nil {
		return 0, false
	}
	status, ok := statuses[progID]
	return status, ok
}

func (coord *multiRuntimeCoordinator) reproQueueLen(runtimeName string) int {
	coord.mu.Lock()
	consumer := coord.consumers[runtimeName]
	runtimeQueue := coord.reproQueues[runtimeName]
	coord.mu.Unlock()
	if consumer != nil {
		return consumer.priorityLen()
	}
	if runtimeQueue == nil {
		return 0
	}
	return runtimeQueue.Len()
}

const shadowPriorityBurst = 4

type shadowProgramSource struct {
	coord    *multiRuntimeCoordinator
	name     string
	consumer *shadowConsumer
	target   *prog.Target
}

func (source *shadowProgramSource) Next() *queue.Request {
	for {
		priorityReq, item, ok := source.consumer.next()
		if !ok {
			return nil
		}
		if priorityReq != nil {
			return priorityReq
		}
		program, err := source.target.Deserialize(item.ProgData, prog.NonStrict)
		if err != nil {
			log.Logf(0, "shadow runtime %q failed to deserialize program %d: %v",
				source.name, item.ID, err)
			source.coord.recordStatus(source.name, item.ID, queue.ExecFailure)
			continue
		}
		if !source.consumer.supports(program) {
			source.coord.recordStatus(source.name, item.ID, queue.Unsupported)
			continue
		}
		req := &queue.Request{
			ProgID:    item.ID,
			Prog:      program,
			Important: item.Important,
		}
		fuzzer.EnableSyscallTrace(req)
		fuzzer.EnableSyscallOutputs(req)
		req.OnDone(func(r *queue.Request, res *queue.Result) bool {
			source.coord.recordResult(source.name, r, res)
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

func (consumer *shadowConsumer) enqueuePriority(req *queue.Request) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.closed {
		return
	}
	consumer.priorityQueue = append(consumer.priorityQueue, req)
	consumer.cond.Signal()
}

func (consumer *shadowConsumer) priorityLen() int {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return len(consumer.priorityQueue)
}

func (consumer *shadowConsumer) next() (*queue.Request, storedProgram, bool) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	for len(consumer.priorityQueue) == 0 && len(consumer.queue) == 0 && !consumer.closed {
		consumer.cond.Wait()
	}
	if len(consumer.priorityQueue) != 0 &&
		(consumer.priorityBurst < shadowPriorityBurst || len(consumer.queue) == 0) {
		req := consumer.priorityQueue[0]
		consumer.priorityQueue[0] = nil
		consumer.priorityQueue = consumer.priorityQueue[1:]
		if consumer.priorityBurst < shadowPriorityBurst {
			consumer.priorityBurst++
		}
		return req, storedProgram{}, true
	}
	if len(consumer.queue) == 0 {
		return nil, storedProgram{}, false
	}
	item := consumer.queue[0]
	consumer.queue[0] = storedProgram{}
	consumer.queue = consumer.queue[1:]
	consumer.priorityBurst = 0
	return nil, item, true
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
