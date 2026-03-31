// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"golang.org/x/sync/errgroup"
)

type DiffFuzzerConfig struct {
	Debug        bool
	PatchedOnly  chan *UniqueBug
	BaseCrashes  chan string
	Store        *DiffFuzzerStore
	ArtifactsDir string // Where to store the artifacts that supplement the logs.
	// The fuzzer waits no more than MaxTriageTime time until it starts taking VMs away
	// for bug reproduction.
	// The option may help find a balance between spending too much time triaging
	// the corpus and not reaching a proper kernel coverage.
	MaxTriageTime time.Duration
	// If non-empty, the fuzzer will spend no more than this amount of time
	// trying to reach the modified code. The time is counted since the moment
	// 99% of the corpus is triaged.
	FuzzToReachPatched time.Duration
	// The callback may be used to consult external systems on whether
	// the crash should be ignored. E.g. because it doesn't match the filter or
	// the particular base kernel has already been seen to crash with the given title.
	// It helps reduce the number of unnecessary reproductions.
	IgnoreCrash func(context.Context, string) (bool, error)
}

func (cfg *DiffFuzzerConfig) TriageDeadline() <-chan time.Time {
	if cfg.MaxTriageTime == 0 {
		return nil
	}
	return time.After(cfg.MaxTriageTime)
}

type UniqueBug struct {
	// The report from the patched kernel.
	Report *report.Report
	Repro  *repro.Result
}

func RunDiffFuzzer(ctx context.Context, baseCfg, newCfg *mgrconfig.Config, cfg DiffFuzzerConfig) error {
	if cfg.PatchedOnly == nil {
		return fmt.Errorf("you must set up a patched only channel")
	}
	stream := queue.NewRandomQueue(4096, rand.New(rand.NewSource(time.Now().UnixNano())))
	seedCh := make(chan []fuzzer.Candidate, 1)
	var http *HTTPServer
	base, err := NewKernelRuntime("base", baseCfg, KernelRuntimeOptions{
		Debug:  cfg.Debug,
		Source: stream,
	})
	if err != nil {
		return err
	}
	if newCfg.HTTP != "" {
		http = &HTTPServer{
			Cfg:       newCfg,
			StartTime: time.Now(),
			DiffStore: cfg.Store,
		}
	}
	new, err := NewKernelRuntime("new", newCfg, KernelRuntimeOptions{
		Debug:         cfg.Debug,
		HTTP:          http,
		Candidates:    seedCh,
		DuplicateInto: stream,
	})
	if err != nil {
		return err
	}
	if http != nil {
		http.Pools = map[string]*vm.Dispatcher{
			new.Name():  new.Pool(),
			base.Name(): base.Pool(),
		}
	}
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		info, err := LoadSeeds(newCfg, true)
		if err != nil {
			return err
		}
		select {
		case seedCh <- info.Candidates:
		case <-ctx.Done():
		}
		return nil
	})

	diffCtx := &diffContext{
		cfg:           cfg,
		doneRepro:     make(chan *ReproResult),
		base:          base,
		new:           new,
		store:         cfg.Store,
		reproAttempts: map[string]int{},
		patchedOnly:   cfg.PatchedOnly,
		http:          http,
	}
	eg.Go(func() error {
		return diffCtx.Loop(ctx)
	})
	return eg.Wait()
}

type diffContext struct {
	cfg   DiffFuzzerConfig
	store *DiffFuzzerStore
	http  *HTTPServer

	doneRepro   chan *ReproResult
	base        *KernelRuntime
	new         *KernelRuntime
	patchedOnly chan *UniqueBug

	mu            sync.Mutex
	reproAttempts map[string]int
}

const (
	// Don't start reproductions until 90% of the corpus has been triaged.
	corpusTriageToRepro = 0.9
	// Start to monitor whether we reached the modified files only after triaging 99%.
	corpusTriageToMonitor = 0.99
)

func (dc *diffContext) Loop(baseCtx context.Context) error {
	g, ctx := errgroup.WithContext(baseCtx)
	reproLoop := NewReproLoop(dc, dc.new.Pool().Total()-dc.new.Config().FuzzingVMs, false)
	if dc.http != nil {
		dc.http.ReproLoop = reproLoop
		g.Go(func() error {
			return dc.http.Serve(ctx)
		})
	}

	g.Go(func() error {
		select {
		case <-ctx.Done():
			return nil
		case <-dc.waitCorpusTriage(ctx, corpusTriageToRepro):
		case <-dc.cfg.TriageDeadline():
			log.Logf(0, "timed out waiting for coprus triage")
		}
		log.Logf(0, "starting bug reproductions")
		reproLoop.Loop(ctx)
		return nil
	})

	g.Go(func() error { return dc.monitorPatchedCoverage(ctx) })
	g.Go(func() error { return dc.base.Loop(ctx) })
	g.Go(func() error { return dc.new.Loop(ctx) })

	runner := &reproRunner{done: make(chan reproRunnerResult, 2), kernel: dc.base}
	statTimer := time.NewTicker(5 * time.Minute)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-statTimer.C:
			vals := make(map[string]int)
			for _, stat := range stat.Collect(stat.All) {
				vals[stat.Name] = stat.V
			}
			data, _ := json.MarshalIndent(vals, "", "  ")
			log.Logf(0, "STAT %s", data)
		case rep := <-dc.base.Crashes():
			log.Logf(1, "base crash: %v", rep.Title)
			dc.reportBaseCrash(ctx, rep)
		case ret := <-runner.done:
			// We have run the reproducer on the base instance.

			// A sanity check: the base kernel might have crashed with the same title
			// since the moment we have stared the reproduction / running on the repro base.
			ignored := dc.ignoreCrash(ctx, ret.reproReport.Title)
			if ret.crashReport == nil && ignored {
				// Report it as error so that we could at least find it in the logs.
				log.Errorf("resulting crash of an approved repro result is to be ignored: %s",
					ret.reproReport.Title)
			} else if ret.crashReport == nil {
				dc.store.BaseNotCrashed(ret.reproReport.Title)
				select {
				case <-ctx.Done():
				case dc.patchedOnly <- &UniqueBug{
					Report: ret.reproReport,
					Repro:  ret.repro,
				}:
				}
				log.Logf(0, "patched-only: %s", ret.reproReport.Title)
				// Now that we know this bug only affects the patch kernel, we can spend more time
				// generating a minimalistic repro and a C repro.
				if !ret.fullRepro {
					reproLoop.Enqueue(&Crash{
						Report: &report.Report{
							Title:  ret.reproReport.Title,
							Output: ret.repro.Prog.Serialize(),
						},
						FullRepro: true,
					})
				}
			} else {
				dc.reportBaseCrash(ctx, ret.crashReport)
				log.Logf(0, "crashes both: %s / %s", ret.reproReport.Title, ret.crashReport.Title)
			}
		case ret := <-dc.doneRepro:
			// We have finished reproducing a crash from the patched instance.
			if ret.Repro != nil && ret.Repro.Report != nil {
				origTitle := ret.Crash.Report.Title
				if ret.Repro.Report.Title == origTitle {
					origTitle = "-SAME-"
				}
				log.Logf(1, "found repro for %q (orig title: %q, reliability: %2.f), took %.2f minutes",
					ret.Repro.Report.Title, origTitle, ret.Repro.Reliability, ret.Stats.TotalTime.Minutes())
				g.Go(func() error {
					runner.Run(ctx, ret.Repro, ret.Crash.FullRepro)
					return nil
				})
			} else {
				origTitle := ret.Crash.Report.Title
				log.Logf(1, "failed repro for %q, err=%s", origTitle, ret.Err)
			}
			dc.store.SaveRepro(ret)
		case rep := <-dc.new.Crashes():
			// A new crash is found on the patched instance.
			crash := &Crash{Report: rep}
			need := dc.NeedRepro(crash)
			log.Logf(0, "patched crashed: %v [need repro = %v]",
				rep.Title, need)
			dc.store.PatchedCrashed(rep.Title, rep.Report, rep.Output)
			if need {
				reproLoop.Enqueue(crash)
			}
		}
	}
	return g.Wait()
}

func (dc *diffContext) ignoreCrash(ctx context.Context, title string) bool {
	if dc.store.EverCrashedBase(title) {
		return true
	}
	// Let's try to ask the external systems about it as well.
	if dc.cfg.IgnoreCrash != nil {
		ignore, err := dc.cfg.IgnoreCrash(ctx, title)
		if err != nil {
			log.Logf(0, "a call to IgnoreCrash failed: %v", err)
		} else {
			if ignore {
				log.Logf(0, "base crash %q is to be ignored", title)
			}
			return ignore
		}
	}
	return false
}

func (dc *diffContext) reportBaseCrash(ctx context.Context, rep *report.Report) {
	dc.store.BaseCrashed(rep.Title, rep.Report)
	if dc.cfg.BaseCrashes == nil {
		return
	}
	select {
	case dc.cfg.BaseCrashes <- rep.Title:
	case <-ctx.Done():
	}
}

func (dc *diffContext) waitCorpusTriage(ctx context.Context, threshold float64) chan struct{} {
	const backOffTime = 30 * time.Second
	ret := make(chan struct{})
	go func() {
		for {
			select {
			case <-time.After(backOffTime):
			case <-ctx.Done():
				return
			}
			triaged := dc.new.TriageProgress()
			if triaged >= threshold {
				log.Logf(0, "triaged %.1f%% of the corpus", triaged*100.0)
				close(ret)
				return
			}
		}
	}()
	return ret
}

var ErrPatchedAreaNotReached = errors.New("fuzzer has not reached the patched area")

func (dc *diffContext) monitorPatchedCoverage(ctx context.Context) error {
	if dc.cfg.FuzzToReachPatched == 0 {
		// The feature is disabled.
		return nil
	}

	// First wait until we have almost triaged all of the corpus.
	select {
	case <-ctx.Done():
		return nil
	case <-dc.waitCorpusTriage(ctx, corpusTriageToMonitor):
	}

	// By this moment, we must have coverage filters already filled out.
	focusPCs := 0
	// The last one is "everything else", so it's not of interest.
	coverFilters := dc.new.coverageFiltersSnapshot()
	for i := 0; i < len(coverFilters.Areas)-1; i++ {
		focusPCs += len(coverFilters.Areas[i].CoverPCs)
	}
	if focusPCs == 0 {
		// No areas were configured.
		log.Logf(1, "no PCs in the areas of focused fuzzing, skipping the zero patched coverage check")
		return nil
	}

	// Then give the fuzzer some change to get through.
	select {
	case <-time.After(dc.cfg.FuzzToReachPatched):
	case <-ctx.Done():
		return nil
	}
	focusAreaStats := dc.new.ProgramsPerArea()
	if focusAreaStats[symbolsArea]+focusAreaStats[filesArea]+focusAreaStats[includesArea] > 0 {
		log.Logf(0, "fuzzer has reached the modified code (%d + %d + %d), continuing fuzzing",
			focusAreaStats[symbolsArea], focusAreaStats[filesArea], focusAreaStats[includesArea])
		return nil
	}
	log.Logf(0, "fuzzer has not reached the modified code in %s, aborting",
		dc.cfg.FuzzToReachPatched)
	return ErrPatchedAreaNotReached
}

// TODO: instead of this limit, consider expotentially growing delays between reproduction attempts.
const maxReproAttempts = 6

func needReproForTitle(title string) bool {
	if strings.Contains(title, "no output") ||
		strings.Contains(title, "lost connection") ||
		strings.Contains(title, "detected stall") ||
		strings.Contains(title, "SYZ") {
		// Don't waste time reproducing these.
		return false
	}
	return true
}

func (dc *diffContext) NeedRepro(crash *Crash) bool {
	if crash.FullRepro {
		return true
	}
	if !needReproForTitle(crash.Title) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if dc.ignoreCrash(ctx, crash.Title) {
		return false
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.reproAttempts[crash.Title] <= maxReproAttempts
}

func (dc *diffContext) RunRepro(ctx context.Context, crash *Crash) *ReproResult {
	dc.mu.Lock()
	dc.reproAttempts[crash.Title]++
	dc.mu.Unlock()

	res, stats, err := repro.Run(ctx, crash.Output, repro.Environment{
		Config:   dc.new.Config(),
		Features: dc.new.Features(),
		Reporter: dc.new.Reporter(),
		Pool:     dc.new.Pool(),
		Fast:     !crash.FullRepro,
	})
	if res != nil && res.Report != nil {
		dc.mu.Lock()
		dc.reproAttempts[res.Report.Title] = maxReproAttempts
		dc.mu.Unlock()
	}
	ret := &ReproResult{
		Crash: crash,
		Repro: res,
		Stats: stats,
		Err:   err,
	}
	select {
	case dc.doneRepro <- ret:
	case <-ctx.Done():
		// If the context is cancelled, no one may be listening on doneRepro.
	}
	return ret
}

func (dc *diffContext) ResizeReproPool(size int) {
	dc.new.Pool().ReserveForRun(size)
}

// reproRunner is used to run reproducers on the base kernel to determine whether it is affected.
type reproRunner struct {
	done    chan reproRunnerResult
	running atomic.Int64
	kernel  *KernelRuntime
}

type reproRunnerResult struct {
	reproReport *report.Report
	crashReport *report.Report
	repro       *repro.Result
	fullRepro   bool // whether this was a full reproduction
}

const (
	// We want to avoid false positives as much as possible, so let's use
	// a stricter relibability cut-off than what's used inside pkg/repro.
	reliabilityCutOff = 0.4
	// 80% reliability x 3 runs is a 0.8% chance of false positives.
	// 6 runs at 40% reproducibility gives a ~4% false positive chance.
	reliabilityThreshold = 0.8
)

// Run executes the reproducer 3 times with slightly different options.
// The objective is to verify whether the bug triggered by the reproducer affects the base kernel.
// To avoid reporting false positives, the function does not require the kernel to crash with exactly
// the same crash title as in the original crash report. Any single crash is accepted.
// The result is sent back over the rr.done channel.
func (rr *reproRunner) Run(ctx context.Context, r *repro.Result, fullRepro bool) {
	if r.Reliability < reliabilityCutOff {
		log.Logf(1, "%s: repro is too unreliable, skipping", r.Report.Title)
		return
	}
	needRuns := 3
	if r.Reliability < reliabilityThreshold {
		needRuns = 6
	}

	pool := rr.kernel.Pool()
	cnt := int(rr.running.Add(1))
	pool.ReserveForRun(min(cnt, pool.Total()))
	defer func() {
		cnt := int(rr.running.Add(-1))
		rr.kernel.Pool().ReserveForRun(min(cnt, pool.Total()))
	}()

	ret := reproRunnerResult{reproReport: r.Report, repro: r, fullRepro: fullRepro}
	for doneRuns := 0; doneRuns < needRuns; {
		if ctx.Err() != nil {
			return
		}
		opts := r.Opts
		opts.Repeat = true
		if doneRuns%3 != 2 {
			// Two times out of 3, test with Threaded=true.
			// The third time we leave it as it was in the reproducer (in case it was important).
			opts.Threaded = true
		}
		var err error
		var result *instance.RunResult
		runErr := pool.Run(ctx, func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
			var ret *instance.ExecProgInstance
			ret, err = instance.SetupExecProg(inst, rr.kernel.Config(), rr.kernel.Reporter(), nil)
			if err != nil {
				return
			}
			result, err = ret.RunSyzProg(instance.ExecParams{
				SyzProg:  r.Prog.Serialize(),
				Duration: max(r.Duration, time.Minute),
				Opts:     opts,
			})
		})
		logPrefix := fmt.Sprintf("attempt #%d to run %q on base", doneRuns, ret.reproReport.Title)
		if errors.Is(runErr, context.Canceled) {
			// Just exit without sending anything over the channel.
			log.Logf(1, "%s: aborting due to context cancelation", logPrefix)
			return
		} else if runErr != nil || err != nil {
			log.Logf(1, "%s: skipping due to errors: %v / %v", logPrefix, runErr, err)
			continue
		}
		doneRuns++
		if result != nil && result.Report != nil {
			log.Logf(1, "%s: crashed with %s", logPrefix, result.Report.Title)
			ret.crashReport = result.Report
			break
		} else {
			log.Logf(1, "%s: did not crash", logPrefix)
		}
	}
	select {
	case rr.done <- ret:
	case <-ctx.Done():
	}
}

const (
	symbolsArea  = "symbols"
	filesArea    = "files"
	includesArea = "included"
)

func PatchFocusAreas(cfg *mgrconfig.Config, gitPatches [][]byte, baseHashes, patchedHashes map[string]string) {
	funcs := modifiedSymbols(baseHashes, patchedHashes)
	if len(funcs) > 0 {
		log.Logf(0, "adding modified_functions to focus areas: %q", funcs)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: symbolsArea,
				Filter: mgrconfig.CovFilterCfg{
					Functions: funcs,
				},
				Weight: 6.0,
			})
	}

	direct, transitive := affectedFiles(cfg, gitPatches)
	if len(direct) > 0 {
		sort.Strings(direct)
		log.Logf(0, "adding directly modified files to focus areas: %q", direct)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: filesArea,
				Filter: mgrconfig.CovFilterCfg{
					Files: direct,
				},
				Weight: 3.0,
			})
	}

	if len(transitive) > 0 {
		sort.Strings(transitive)
		log.Logf(0, "adding transitively affected to focus areas: %q", transitive)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: includesArea,
				Filter: mgrconfig.CovFilterCfg{
					Files: transitive,
				},
				Weight: 2.0,
			})
	}

	// Still fuzz the rest of the kernel.
	if len(cfg.Experimental.FocusAreas) > 0 {
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Weight: 1.0,
			})
	}
}

func affectedFiles(cfg *mgrconfig.Config, gitPatches [][]byte) (direct, transitive []string) {
	const maxAffectedByHeader = 50

	directMap := make(map[string]struct{})
	transitiveMap := make(map[string]struct{})
	var allFiles []string
	for _, patch := range gitPatches {
		allFiles = append(allFiles, vcs.ParseGitDiff(patch)...)
	}
	for _, file := range allFiles {
		directMap[file] = struct{}{}
		if strings.HasSuffix(file, ".h") && cfg.KernelSrc != "" {
			// For .h files, we want to determine all the .c files that include them.
			// Ideally, we should combine this with the recompilation process - then we know
			// exactly which files were affected by the patch.
			matching, err := osutil.GrepFiles(cfg.KernelSrc, `.c`,
				[]byte(`<`+strings.TrimPrefix(file, "include/")+`>`))
			if err != nil {
				log.Logf(0, "failed to grep for includes: %s", err)
				continue
			}
			if len(matching) >= maxAffectedByHeader {
				// It's too widespread. It won't help us focus on anything.
				log.Logf(0, "the header %q is included in too many files (%d)", file, len(matching))
				continue
			}
			for _, name := range matching {
				transitiveMap[name] = struct{}{}
			}
		}
	}
	for name := range directMap {
		direct = append(direct, name)
	}
	for name := range transitiveMap {
		if _, ok := directMap[name]; ok {
			continue
		}
		transitive = append(transitive, name)
	}
	return
}

// If there are too many different symbols, they are no longer specific enough.
// Don't use them to focus the fuzzer.
const modifiedSymbolThreshold = 0.05

func modifiedSymbols(baseHashes, patchedHashes map[string]string) []string {
	var ret []string
	for name, hash := range patchedHashes {
		if baseHash, ok := baseHashes[name]; !ok || baseHash != hash {
			ret = append(ret, name)
			if float64(len(ret)) > float64(len(patchedHashes))*modifiedSymbolThreshold {
				return nil
			}
		}
	}
	sort.Strings(ret)
	return ret
}
