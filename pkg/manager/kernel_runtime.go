// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"golang.org/x/sync/errgroup"
)

type KernelRuntimeOptions struct {
	Debug           bool
	HTTP            *HTTPServer
	Candidates      <-chan []fuzzer.Candidate
	Source          queue.Source
	DuplicateInto   queue.Executor
	RPCManager      rpcserver.Manager
	InstanceHandler func(context.Context, *vm.Instance, dispatcher.UpdateInfo)
	Stats           rpcserver.Stats
}

// KernelRuntime encapsulates per-kernel runtime state: RPC server, VM pool/dispatcher,
// machine-check results and the runtime-local fuzzer state used by patch fuzzing.
type KernelRuntime struct {
	name   string
	ctx    context.Context
	debug  bool
	cfg    *mgrconfig.Config
	http   *HTTPServer
	source queue.Source

	reporter  *report.Reporter
	fuzzer    atomic.Pointer[fuzzer.Fuzzer]
	servMu    sync.RWMutex
	serv      rpcserver.Server
	listening bool
	servStats rpcserver.Stats
	crashes   chan *report.Report
	vmPool    *vm.Pool
	pool      *vm.Dispatcher
	features  flatrpc.Feature

	candidates    <-chan []fuzzer.Candidate
	duplicateInto queue.Executor
	// Once candidates is assigned, candidatesCount holds their original count.
	candidatesCount atomic.Int64

	coverFilters    CoverageFilters
	reportGenerator *ReportGeneratorWrapper
}

func NewKernelRuntime(name string, cfg *mgrconfig.Config, opts KernelRuntimeOptions) (*KernelRuntime, error) {
	osutil.MkdirAll(cfg.Workdir)

	candidates := opts.Candidates
	if candidates == nil {
		ch := make(chan []fuzzer.Candidate)
		close(ch)
		candidates = ch
	}

	runtime := &KernelRuntime{
		name:            name,
		debug:           opts.Debug,
		cfg:             cfg,
		http:            opts.HTTP,
		source:          opts.Source,
		candidates:      candidates,
		duplicateInto:   opts.DuplicateInto,
		crashes:         make(chan *report.Report, 128),
		reportGenerator: ReportGeneratorCache(cfg),
	}
	if opts.Stats.StatExecs != nil {
		runtime.servStats = opts.Stats
	} else {
		runtime.servStats = rpcserver.NewNamedStats(name)
	}

	var err error
	runtime.reporter, err = report.NewReporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create reporter for %q: %w", name, err)
	}

	rpcManager := opts.RPCManager
	if rpcManager == nil {
		rpcManager = runtime
	}
	runtime.serv, err = rpcserver.New(&rpcserver.RemoteConfig{
		Config:  cfg,
		Manager: rpcManager,
		Stats:   runtime.servStats,
		Debug:   opts.Debug,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc server for %q: %w", name, err)
	}

	if !cfg.VMLess {
		vmPool, err := vm.Create(cfg, opts.Debug)
		if err != nil {
			return nil, fmt.Errorf("failed to create vm.Pool for %q: %w", name, err)
		}
		runtime.vmPool = vmPool
		instanceHandler := opts.InstanceHandler
		if instanceHandler == nil {
			instanceHandler = runtime.fuzzerInstance
		}
		runtime.pool = vm.NewDispatcher(vmPool, instanceHandler)
	}
	return runtime, nil
}

func (runtime *KernelRuntime) Name() string {
	return runtime.name
}

func (runtime *KernelRuntime) Config() *mgrconfig.Config {
	return runtime.cfg
}

func (runtime *KernelRuntime) Pool() *vm.Dispatcher {
	return runtime.pool
}

func (runtime *KernelRuntime) Server() rpcserver.Server {
	runtime.servMu.RLock()
	defer runtime.servMu.RUnlock()
	return runtime.serv
}

func (runtime *KernelRuntime) Reporter() *report.Reporter {
	return runtime.reporter
}

func (runtime *KernelRuntime) Features() flatrpc.Feature {
	return runtime.features
}

func (runtime *KernelRuntime) Crashes() <-chan *report.Report {
	return runtime.crashes
}

func (runtime *KernelRuntime) CloseServer() error {
	runtime.servMu.Lock()
	serv := runtime.serv
	listening := runtime.listening
	runtime.serv = nil
	runtime.listening = false
	runtime.servMu.Unlock()
	if serv == nil || !listening {
		return nil
	}
	return serv.Close()
}

func (runtime *KernelRuntime) ListenServer() error {
	runtime.servMu.Lock()
	defer runtime.servMu.Unlock()
	if runtime.serv == nil {
		return fmt.Errorf("runtime server is not available")
	}
	if runtime.listening {
		return nil
	}
	if err := runtime.serv.Listen(); err != nil {
		return err
	}
	runtime.listening = true
	return nil
}

func (runtime *KernelRuntime) Close() error {
	if err := runtime.CloseServer(); err != nil {
		return err
	}
	if runtime.vmPool != nil {
		return runtime.vmPool.Close()
	}
	return nil
}

func (runtime *KernelRuntime) coverageFiltersSnapshot() CoverageFilters {
	return runtime.coverFilters
}

func (runtime *KernelRuntime) Loop(baseCtx context.Context) error {
	defer log.Logf(1, "%s: kernel runtime loop terminated", runtime.name)

	serv := runtime.Server()
	if serv == nil {
		return fmt.Errorf("runtime server is not available")
	}
	if err := runtime.ListenServer(); err != nil {
		return fmt.Errorf("failed to start rpc server: %w", err)
	}
	eg, ctx := errgroup.WithContext(baseCtx)
	runtime.ctx = ctx
	eg.Go(func() error {
		defer log.Logf(1, "%s: rpc server terminaled", runtime.name)
		return serv.Serve(ctx)
	})
	if runtime.pool != nil {
		eg.Go(func() error {
			defer log.Logf(1, "%s: pool terminated", runtime.name)
			runtime.pool.Loop(ctx)
			return nil
		})
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case err := <-runtime.pool.BootErrors:
					title := "unknown"
					var bootErr vm.BootErrorer
					if errors.As(err, &bootErr) {
						title, _ = bootErr.BootError()
					}
					// Boot errors are not useful for patch fuzzing (at least yet).
					// Fetch them to not block the channel and print them to the logs.
					log.Logf(0, "%s: boot error: %s", runtime.name, title)
				}
			}
		})
	}
	return eg.Wait()
}

func (runtime *KernelRuntime) MaxSignal() signal.Signal {
	if fuzzer := runtime.fuzzer.Load(); fuzzer != nil {
		return fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (runtime *KernelRuntime) BugFrames() (leaks, races []string) {
	return nil, nil
}

func (runtime *KernelRuntime) MachineChecked(features flatrpc.Feature,
	syscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(syscalls) == 0 {
		return nil, fmt.Errorf("all system calls are disabled")
	}
	log.Logf(0, "%s: machine check complete", runtime.name)
	runtime.features = features

	var source queue.Source
	if runtime.source != nil {
		source = runtime.source
	} else {
		source = runtime.setupFuzzer(features, syscalls)
		if runtime.duplicateInto != nil {
			source = queue.Tee(source, runtime.duplicateInto)
		}
	}
	opts := fuzzer.DefaultExecOpts(runtime.cfg, features, runtime.debug)
	return queue.DefaultOpts(source, opts), nil
}

func (runtime *KernelRuntime) setupFuzzer(features flatrpc.Feature,
	syscalls map[*prog.Syscall]bool) queue.Source {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	corpusObj := corpus.NewFocusedCorpus(runtime.ctx, nil, runtime.coverFilters.Areas)
	fuzzerObj := fuzzer.NewFuzzer(runtime.ctx, &fuzzer.Config{
		Corpus:   corpusObj,
		Coverage: runtime.cfg.Cover,
		// Fault injection may bring instaibility into bug reproducibility, which may lead to false positives.
		FaultInjection: false,
		Comparisons:    features&flatrpc.FeatureComparisons != 0,
		Collide:        true,
		EnabledCalls:   syscalls,
		NoMutateCalls:  runtime.cfg.NoMutateCalls,
		PatchTest:      true,
		Workdir:        runtime.cfg.Workdir,
		Logf: func(level int, msg string, args ...interface{}) {
			if level != 0 {
				return
			}
			log.Logf(level, msg, args...)
		},
	}, rnd, runtime.cfg.Target)

	if runtime.http != nil {
		runtime.http.Fuzzer.Store(fuzzerObj)
		runtime.http.EnabledSyscalls.Store(syscalls)
		runtime.http.Corpus.Store(corpusObj)
	}

	var candidates []fuzzer.Candidate
	select {
	case candidates = <-runtime.candidates:
	case <-runtime.ctx.Done():
		// The loop will be aborted later.
	}
	// We assign runtime.fuzzer after runtime.candidatesCount to simplify TriageProgress().
	runtime.candidatesCount.Store(int64(len(candidates)))
	runtime.fuzzer.Store(fuzzerObj)

	filtered := FilterCandidates(candidates, syscalls, false).Candidates
	log.Logf(0, "%s: adding %d seeds", runtime.name, len(filtered))
	fuzzerObj.AddCandidates(filtered)

	go func() {
		if !runtime.cfg.Cover {
			return
		}
		for {
			select {
			case <-time.After(time.Second):
			case <-runtime.ctx.Done():
				return
			}
			newSignal := fuzzerObj.Cover.GrabSignalDelta()
			if len(newSignal) == 0 {
				continue
			}
			runtime.serv.DistributeSignalDelta(newSignal)
		}
	}()
	return fuzzerObj
}

func (runtime *KernelRuntime) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	runtime.reportGenerator.Init(modules)
	filters, err := PrepareCoverageFilters(runtime.reportGenerator, runtime.cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to init coverage filter: %w", err)
	}
	runtime.coverFilters = filters
	for _, area := range filters.Areas {
		log.Logf(0, "area %q: %d PCs in the cover filter",
			area.Name, len(area.CoverPCs))
	}
	log.Logf(0, "executor cover filter: %d PCs", len(filters.ExecutorFilter))
	if runtime.http != nil {
		runtime.http.Cover.Store(&CoverageInfo{
			Modules:         modules,
			ReportGenerator: runtime.reportGenerator,
			CoverFilter:     filters.ExecutorFilter,
		})
	}
	var pcs []uint64
	for pc := range filters.ExecutorFilter {
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

func (runtime *KernelRuntime) fuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	serv := runtime.Server()
	if serv == nil {
		return
	}
	index := inst.Index()
	injectExec := make(chan bool, 10)
	serv.CreateInstance(index, injectExec, updInfo)
	rep, err := runtime.runInstance(ctx, inst, injectExec)
	lastExec, _ := serv.ShutdownInstance(index, rep != nil)
	if rep != nil {
		rpcserver.PrependExecuting(rep, lastExec)
		select {
		case runtime.crashes <- rep:
		case <-ctx.Done():
		}
	}
	if err != nil {
		log.Errorf("#%d run failed: %s", inst.Index(), err)
	}
}

func (runtime *KernelRuntime) runInstance(ctx context.Context, inst *vm.Instance,
	injectExec <-chan bool) (*report.Report, error) {
	serv := runtime.Server()
	if serv == nil {
		return nil, fmt.Errorf("runtime server is not available")
	}
	fwdAddr, err := inst.Forward(serv.Port())
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}
	executorBin, err := inst.Copy(runtime.cfg.ExecutorBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %w", err)
	}
	host, port, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manager's address")
	}
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	ctxTimeout, cancel := context.WithTimeout(ctx, runtime.cfg.Timeouts.VMRunningTime)
	defer cancel()
	_, reps, err := inst.Run(ctxTimeout, runtime.Reporter(), cmd,
		vm.WithExitCondition(vm.ExitTimeout),
		vm.WithInjectExecuting(injectExec),
		vm.WithEarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			serv.StopFuzzing(inst.Index())
		}),
	)
	if len(reps) > 0 {
		return reps[0], err
	}
	return nil, err
}

func (runtime *KernelRuntime) TriageProgress() float64 {
	fuzzerObj := runtime.fuzzer.Load()
	if fuzzerObj == nil {
		return 0
	}
	total := runtime.candidatesCount.Load()
	if total == 0 {
		// There were no candidates in the first place.
		return 1
	}
	return 1.0 - float64(fuzzerObj.CandidatesToTriage())/float64(total)
}

func (runtime *KernelRuntime) ProgramsPerArea() map[string]int {
	fuzzerObj := runtime.fuzzer.Load()
	if fuzzerObj == nil {
		return nil
	}
	return fuzzerObj.Config.Corpus.ProgsPerArea()
}
