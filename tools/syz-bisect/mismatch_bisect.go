// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

const (
	mismatchTestSamples           = 3
	mismatchDefaultRuntimeTimeout = 10 * time.Minute
	mismatchRuntimeStopTimeout    = 30 * time.Second
	mismatchBatchWorkspaceName    = ".syz-bisect-work"
	mismatchBatchWorkspaceMarker  = "workspace.version"
)

// Batch workspaces are shared only by the serial candidate loop in one
// syz-bisect process. Concurrent invocations for the same report directory are
// intentionally not coordinated yet.
type mismatchBisectWorkspace struct {
	RootDir   string
	KernelDir string
	WorkDir   string
}

// bisectMismatch runs the same source-build and git-bisect machinery as the
// regular syz-bisect command, but uses a runtime behavior predicate instead of
// a crash report predicate. Single-report mode keeps mutable kernel state under
// the program directory. Batch mode passes one workspace shared sequentially by
// every program in the batch.
func bisectMismatch(candidate *mismatchCandidate, managerCfg *mgrconfig.Config,
	sharedWorkspace *mismatchBisectWorkspace) error {
	if candidate == nil || candidate.History.Good == nil || candidate.History.Bad == nil {
		return fmt.Errorf("mismatch history has no bisection endpoints")
	}
	for _, difference := range candidate.Report.StableDifferences {
		if difference.Kind == "output" {
			return fmt.Errorf("output differences are not yet executable by syz-bisect")
		}
	}
	badCfg := configForRuntime(managerCfg, candidate.History.Bad.Name)
	if badCfg == nil {
		return fmt.Errorf("runtime %q is not present in manager config", candidate.History.Bad.Name)
	}
	if badCfg.TargetOS != targets.Linux {
		return fmt.Errorf("runtime bisection currently supports linux kernels, got %q", badCfg.TargetOS)
	}
	source := badCfg.KernelSrc
	if source == "" {
		source = badCfg.KernelObj
	}
	if source == "" {
		return fmt.Errorf("runtime %q has no kernel source", badCfg.Name)
	}
	goodHash := candidate.History.Good.Commit.Hash
	badHash := candidate.History.Bad.Commit.Hash
	artifactDir := filepath.Join(candidate.Dir, "bisect")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return err
	}
	trace := &debugtracer.GenericTracer{TraceWriter: os.Stdout, OutDir: artifactDir}
	kernelDir := filepath.Join(artifactDir, "kernel")
	workDir := filepath.Join(artifactDir, "work")
	if sharedWorkspace != nil {
		kernelDir = sharedWorkspace.KernelDir
		workDir = sharedWorkspace.WorkDir
		if err := resetMismatchBatchWorkdir(sharedWorkspace); err != nil {
			return err
		}
		trace.Logf("using shared batch workspace %s", sharedWorkspace.RootDir)
	}
	if err := cloneKernelRepo(source, kernelDir); err != nil {
		return err
	}

	workingCfg := cloneRuntimeConfig(badCfg, workDir, kernelDir)
	workingCfg.Cover = false
	trace.Logf("mismatch runtime config: snapshot-isolated samples enabled")
	// A bisect predicate needs repeated executions, not the manager's full
	// fuzzing pool. One VM keeps each commit test bounded and avoids competing
	// with the live manager for resources.
	if err := instance.OverrideVMCount(workingCfg, 1); err != nil {
		return fmt.Errorf("limit bisection VM count: %w", err)
	}
	if err := os.MkdirAll(workingCfg.Workdir, 0o755); err != nil {
		return err
	}
	kernelConfig, err := loadKernelConfig(badCfg)
	if err != nil {
		return err
	}
	compiler, compilerType := mismatchCompiler(kernelConfig)
	inst, err := instance.NewEnv(workingCfg, nil, nil)
	if err != nil {
		return err
	}
	// This is a disposable private clone. Leave it non-precious so an
	// interrupted invocation can reset an in-progress git bisect on retry.
	repo, err := vcs.NewRepo(workingCfg.TargetOS, workingCfg.Type, kernelDir)
	if err != nil {
		return err
	}
	if sharedWorkspace != nil {
		if err := prepareSharedKernelRepo(repo, source, goodHash, badHash); err != nil {
			return err
		}
	}
	bisecter, ok := repo.(vcs.Bisecter)
	if !ok {
		return fmt.Errorf("kernel repository does not support bisection")
	}
	if err := bisecter.PrepareBisect(); err != nil {
		return fmt.Errorf("prepare kernel bisection: %w", err)
	}

	pdata, err := os.ReadFile(candidate.ReproPath)
	if err != nil {
		return fmt.Errorf("read minimized reproducer: %w", err)
	}
	repro, err := workingCfg.Target.Deserialize(pdata, prog.NonStrict)
	if err != nil {
		return fmt.Errorf("parse minimized reproducer: %w", err)
	}
	goodKey, err := mismatchBehaviorKey(&candidate.Report, candidate.History.Good.Name)
	if err != nil {
		return err
	}
	badKey, err := mismatchBehaviorKey(&candidate.Report, candidate.History.Bad.Name)
	if err != nil {
		return err
	}
	cache := make(map[string]vcs.BisectResult)
	testCommit := func(hash string) (vcs.BisectResult, error) {
		if result, ok := cache[hash]; ok {
			return result, nil
		}
		if _, err := repo.SwitchCommit(hash); err != nil {
			return vcs.BisectSkip, err
		}
		current, err := repo.Commit(vcs.HEAD)
		if err != nil {
			return vcs.BisectSkip, err
		}
		trace.Logf("testing kernel commit %s", current.Hash)
		bisectEnv, err := bisecter.EnvForCommit(compiler, compilerType, "", current.Hash,
			kernelConfig, nil)
		if err != nil {
			trace.Logf("cannot select build environment for %s: %v", current.Hash, err)
			cache[hash] = vcs.BisectSkip
			return vcs.BisectSkip, nil
		}
		if !compilerAvailable(bisectEnv.Compiler) && compilerAvailable(compiler) {
			// The manager config does not have the legacy syz-bisect bin_dir
			// knob. Use the host compiler when a historical version is not
			// installed; the build result is still classified conservatively.
			trace.Logf("compiler %q is unavailable, falling back to %q", bisectEnv.Compiler, compiler)
			bisectEnv.Compiler = compiler
		}
		buildCfg := &instance.BuildKernelConfig{
			MakeBin:      instance.MakeBin,
			CompilerBin:  bisectEnv.Compiler,
			KernelConfig: bisectEnv.KernelConfig,
			UserspaceDir: badCfg.Image,
			BuildCPUs:    runtime.GOMAXPROCS(0),
		}
		if err := inst.CleanKernel(buildCfg); err != nil {
			trace.Logf("kernel clean failed for %s: %v", current.Hash, err)
			cache[hash] = vcs.BisectSkip
			return vcs.BisectSkip, nil
		}
		if _, _, err := inst.BuildKernel(buildCfg); err != nil {
			trace.Logf("kernel build failed for %s: %v", current.Hash, err)
			cache[hash] = vcs.BisectSkip
			return vcs.BisectSkip, nil
		}
		trace.Logf("kernel build completed for %s; starting runtime samples", current.Hash)
		key, err := runMismatchSamples(workingCfg, candidate.Report, repro)
		if err != nil {
			trace.Logf("runtime test failed for %s: %v", current.Hash, err)
			cache[hash] = vcs.BisectSkip
			return vcs.BisectSkip, nil
		}
		result := vcs.BisectSkip
		switch key {
		case goodKey:
			result = vcs.BisectGood
		case badKey:
			result = vcs.BisectBad
		default:
			trace.Logf("commit %s produced an unobserved runtime behavior %s", current.Hash, key)
		}
		cache[hash] = result
		return result, nil
	}

	goodResult, err := testCommit(goodHash)
	if err != nil {
		return err
	}
	if goodResult != vcs.BisectGood {
		return fmt.Errorf("good endpoint %s did not reproduce behavior A", goodHash)
	}
	badResult, err := testCommit(badHash)
	if err != nil {
		return err
	}
	if badResult != vcs.BisectBad {
		return fmt.Errorf("bad endpoint %s did not reproduce behavior B", badHash)
	}
	commits, err := bisecter.Bisect(badHash, goodHash, trace, func() (vcs.BisectResult, error) {
		current, err := repo.Commit(vcs.HEAD)
		if err != nil {
			return vcs.BisectSkip, err
		}
		return testCommit(current.Hash)
	})
	if err != nil {
		return err
	}
	if len(commits) != 1 {
		return fmt.Errorf("bisection is inconclusive (%d candidate commits)", len(commits))
	}
	if err := osutil.WriteFileAtomically(filepath.Join(candidate.Dir, mismatchCauseFile),
		[]byte(commits[0].Hash+"\n")); err != nil {
		return fmt.Errorf("save cause commit: %w", err)
	}
	fmt.Fprintf(os.Stdout, "prog %d: cause commit %s (%s)\n",
		candidate.ProgID, commits[0].Hash, commits[0].Title)
	return nil
}

func prepareMismatchBatchWorkspace(reportDir string) (*mismatchBisectWorkspace, error) {
	rootDir := filepath.Join(reportDir, mismatchBatchWorkspaceName)
	marker := filepath.Join(rootDir, mismatchBatchWorkspaceMarker)
	info, err := os.Lstat(rootDir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("batch workspace %q is not a directory", rootDir)
		}
		data, err := os.ReadFile(marker)
		if err != nil {
			return nil, fmt.Errorf("existing batch workspace %q has no valid marker: %w", rootDir, err)
		}
		if string(data) != "1\n" {
			return nil, fmt.Errorf("batch workspace %q has unsupported marker %q", rootDir, data)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(rootDir, 0o755); err != nil {
			return nil, err
		}
		if err := osutil.WriteFileAtomically(marker, []byte("1\n")); err != nil {
			_ = os.Remove(rootDir)
			return nil, fmt.Errorf("write batch workspace marker: %w", err)
		}
	default:
		return nil, fmt.Errorf("stat batch workspace %q: %w", rootDir, err)
	}
	workspace := &mismatchBisectWorkspace{
		RootDir:   rootDir,
		KernelDir: filepath.Join(rootDir, "kernel"),
		WorkDir:   filepath.Join(rootDir, "work"),
	}
	if err := removeLegacyMismatchWorkspaces(reportDir); err != nil {
		return nil, err
	}
	return workspace, nil
}

// removeLegacyMismatchWorkspaces removes only the large mutable directories
// created by the old per-program layout. Per-program logs and result markers
// remain in place.
func removeLegacyMismatchWorkspaces(reportDir string) error {
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return fmt.Errorf("read mismatch report directory %q: %w", reportDir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, ok := mismatchProgID(entry.Name()); !ok {
			continue
		}
		artifactDir := filepath.Join(reportDir, entry.Name(), "bisect")
		info, err := os.Lstat(artifactDir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat per-program artifact directory %q: %w", artifactDir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("refusing to clean non-directory per-program artifact path %q", artifactDir)
		}
		for _, name := range []string{"kernel", "work"} {
			path := filepath.Join(artifactDir, name)
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("remove legacy workspace %q: %w", path, err)
			}
		}
	}
	return nil
}

func resetMismatchBatchWorkdir(workspace *mismatchBisectWorkspace) error {
	if workspace == nil {
		return fmt.Errorf("nil batch workspace")
	}
	if err := os.RemoveAll(workspace.WorkDir); err != nil {
		return fmt.Errorf("reset shared workdir %q: %w", workspace.WorkDir, err)
	}
	if err := os.MkdirAll(workspace.WorkDir, 0o755); err != nil {
		return fmt.Errorf("create shared workdir %q: %w", workspace.WorkDir, err)
	}
	return nil
}

// prepareSharedKernelRepo resets any checkout/bisect/build state left by the
// preceding program. CheckoutCommit fetches a full hash from source only when
// the shared clone does not already contain it. Fetching the bad endpoint also
// brings in the ancestry needed for git bisect.
func prepareSharedKernelRepo(repo vcs.Repo, source, goodHash, badHash string) error {
	if _, err := repo.CheckoutCommit(source, goodHash); err != nil {
		return fmt.Errorf("prepare shared kernel at good endpoint %s: %w", goodHash, err)
	}
	present, err := repo.CommitExists(badHash)
	if err != nil {
		return fmt.Errorf("check bad endpoint %s in shared kernel: %w", badHash, err)
	}
	if !present {
		if _, err := repo.CheckoutCommit(source, badHash); err != nil {
			return fmt.Errorf("fetch bad endpoint %s into shared kernel: %w", badHash, err)
		}
	}
	return nil
}

func cloneRuntimeConfig(src *mgrconfig.Config, workdir, kernelDir string) *mgrconfig.Config {
	ret := *src
	ret.Workdir = workdir
	ret.KernelSrc = kernelDir
	ret.KernelBuildSrc = ""
	ret.KernelObj = filepath.Join(workdir, "kernel-obj")
	ret.PrimaryRuntime = ""
	ret.ComparisonPrimary = ""
	ret.Runtimes = nil
	ret.RuntimeConfigs = nil
	// Every sample must start from the same VM state. This is the same
	// snapshot-isolated execution mode used by syz-manager's
	// comparison/shadow runtimes. executeMismatchProgram submits samples
	// serially, while the snapshot backend restores the shared snapshot before
	// each request.
	ret.Snapshot = true
	return &ret
}

func cloneKernelRepo(source, destination string) error {
	if info, err := os.Stat(destination); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("kernel clone destination %q is not a directory", destination)
		}
		if _, err := os.Stat(filepath.Join(destination, ".git")); err == nil {
			return nil
		}
		return fmt.Errorf("kernel clone destination %q already exists", destination)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if _, err := osutil.RunCmd(time.Hour, "", "git", "clone", "--shared", "--no-checkout",
		source, destination); err != nil {
		return fmt.Errorf("clone kernel repository %q: %w", source, err)
	}
	return nil
}

func loadKernelConfig(cfg *mgrconfig.Config) ([]byte, error) {
	paths := []string{}
	for _, dir := range []string{cfg.KernelObj, cfg.KernelBuildSrc, cfg.KernelSrc} {
		if dir != "" {
			paths = append(paths, filepath.Join(dir, ".config"), filepath.Join(dir, "kernel.config"))
		}
	}
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil && len(data) != 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("cannot find kernel .config in runtime %q", cfg.Name)
}

func mismatchCompiler(config []byte) (compiler, compilerType string) {
	if strings.Contains(string(config), "CONFIG_CC_IS_CLANG=y") {
		return "clang", "clang"
	}
	return "gcc", "gcc"
}

func compilerAvailable(compiler string) bool {
	if compiler == "" {
		return false
	}
	if strings.ContainsRune(compiler, filepath.Separator) {
		_, err := os.Stat(compiler)
		return err == nil
	}
	_, err := exec.LookPath(compiler)
	return err == nil
}

// runMismatchSamples executes the same minimized program several times on a
// candidate kernel. It returns a behavior digest only when every sample is
// identical; otherwise the commit is skipped as an unstable observation.
func runMismatchSamples(cfg *mgrconfig.Config, report storedMismatchForBisect,
	repro *prog.Prog) (string, error) {
	if repro == nil {
		return "", fmt.Errorf("nil reproducer")
	}
	results, err := executeMismatchProgram(cfg, repro, mismatchTestSamples)
	if err != nil {
		return "", err
	}
	var key string
	for _, result := range results {
		if result.Status == queue.Unsupported {
			return "", fmt.Errorf("candidate runtime does not support the reproducer")
		}
		current, err := candidateBehaviorKey(&report, repro, result)
		if err != nil {
			return "", err
		}
		if key == "" {
			key = current
		} else if key != current {
			return "", fmt.Errorf("candidate behavior is unstable (%s then %s)", key, current)
		}
	}
	return key, nil
}

func executeMismatchProgram(cfg *mgrconfig.Config, repro *prog.Prog, samples int) (results []*queue.Result, retErr error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil manager config")
	}
	if repro == nil {
		return nil, fmt.Errorf("nil reproducer")
	}
	if samples <= 0 {
		return nil, fmt.Errorf("invalid sample count %d", samples)
	}
	source := queue.Plain()
	kernelRuntime, err := manager.NewKernelRuntime("syz-bisect", cfg, manager.KernelRuntimeOptions{
		Debug:  true,
		Source: source,
	})
	if err != nil {
		return nil, err
	}
	timeout := mismatchRuntimeTimeout(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	loopDone := make(chan error, 1)
	go func() {
		err := kernelRuntime.Loop(ctx)
		loopDone <- err
	}()
	log.Logf(0, "syz-bisect: starting mismatch runtime (%d samples, timeout %v, snapshot=%v)",
		samples, timeout, cfg.Snapshot)
	loopObserved := false
	defer func() {
		cancel()
		var loopErr error
		waitForLoop := func() bool {
			select {
			case loopErr = <-loopDone:
				loopObserved = true
				return true
			case <-time.After(mismatchRuntimeStopTimeout):
				return false
			}
		}
		if !loopObserved && !waitForLoop() {
			// KernelRuntime.Close also closes the VM pool, which requires every
			// instance to have already exited. Close only the RPC listener first
			// when the dispatcher did not stop after cancellation; this avoids the
			// pool.Close panic while giving the runner another chance to unwind.
			log.Logf(0, "syz-bisect: kernel runtime did not stop within %v; closing RPC server",
				mismatchRuntimeStopTimeout)
			if err := kernelRuntime.CloseServer(); err != nil && !mismatchShutdownErrorExpected(err) {
				if retErr == nil {
					retErr = fmt.Errorf("close kernel runtime server: %w", err)
				} else {
					log.Logf(0, "syz-bisect: failed to close kernel runtime server after test error: %v", err)
				}
			}
			if !waitForLoop() {
				if retErr == nil {
					retErr = fmt.Errorf("timed out stopping kernel runtime after %v", 2*mismatchRuntimeStopTimeout)
				} else {
					log.Logf(0, "syz-bisect: timed out stopping kernel runtime after test error")
				}
			}
		}
		if loopObserved {
			if loopErr != nil && !mismatchShutdownErrorExpected(loopErr) {
				if retErr == nil {
					retErr = fmt.Errorf("kernel runtime cleanup failed: %w", loopErr)
				} else {
					log.Logf(0, "syz-bisect: kernel runtime cleanup failed after test error: %v", loopErr)
				}
			}
			if err := kernelRuntime.Close(); err != nil && !mismatchShutdownErrorExpected(err) {
				if retErr == nil {
					retErr = fmt.Errorf("close kernel runtime: %w", err)
				} else {
					log.Logf(0, "syz-bisect: failed to close kernel runtime after test error: %v", err)
				}
			}
		}
	}()
	results = make([]*queue.Result, 0, samples)
	for i := 0; i < samples; i++ {
		// Use one stable non-zero ID for all samples, like syz-manager does for
		// repeated repro requests. This keeps the execution mode identical
		// across samples while still forcing synchronous syscall execution.
		req := &queue.Request{Prog: repro.Clone(), ProgID: 1, Important: true}
		fuzzer.EnableSyscallTrace(req)
		fuzzer.EnableSyscallOutputs(req)
		source.Submit(req)
		log.Logf(0, "syz-bisect: submitted mismatch sample %d/%d", i+1, samples)

		sampleResults, observed, err := waitMismatchResults(ctx, []*queue.Request{req}, loopDone)
		if observed {
			loopObserved = true
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("mismatch runtime test timed out after %v: %w", timeout, err)
			}
			return nil, err
		}
		if len(sampleResults) != 1 || sampleResults[0] == nil {
			return nil, fmt.Errorf("runtime returned no result for mismatch sample %d", i+1)
		}
		results = append(results, sampleResults[0])
	}
	log.Logf(0, "syz-bisect: all %d mismatch samples completed", len(results))
	return results, nil
}

func mismatchShutdownErrorExpected(err error) bool {
	return err == nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed)
}

func mismatchRuntimeTimeout(cfg *mgrconfig.Config) time.Duration {
	if cfg != nil && cfg.Timeouts.VMRunningTime > 0 &&
		cfg.Timeouts.VMRunningTime < mismatchDefaultRuntimeTimeout {
		return cfg.Timeouts.VMRunningTime
	}
	return mismatchDefaultRuntimeTimeout
}

type mismatchSampleResult struct {
	index  int
	result *queue.Result
}

// waitMismatchResults waits for both request completion and runtime failure.
// Request.Wait alone cannot report that the runtime loop has exited, so each
// request is waited in a small goroutine while the caller also monitors
// loopDone. The result channel is buffered to let those goroutines finish when
// an early runtime error aborts the collection.
func waitMismatchResults(ctx context.Context, requests []*queue.Request,
	loopDone <-chan error) (results []*queue.Result, loopObserved bool, retErr error) {
	if len(requests) == 0 {
		return nil, false, fmt.Errorf("no mismatch requests")
	}
	completed := make(chan mismatchSampleResult, len(requests))
	for i, req := range requests {
		go func(index int, request *queue.Request) {
			completed <- mismatchSampleResult{index: index, result: request.Wait(ctx)}
		}(i, req)
	}
	results = make([]*queue.Result, len(requests))
	finished := 0
	for finished < len(requests) {
		select {
		case sample := <-completed:
			if sample.result == nil {
				return nil, false, fmt.Errorf("runtime returned no result for sample %d", sample.index+1)
			}
			if sample.result.Status == queue.ExecFailure &&
				errors.Is(sample.result.Err, queue.ErrRequestAborted) {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, false, fmt.Errorf("waiting for mismatch samples (%d/%d complete): %w",
						finished, len(requests), ctxErr)
				}
				return nil, false, sample.result.Err
			}
			results[sample.index] = sample.result
			finished++
			log.Logf(0, "syz-bisect: mismatch sample %d/%d completed (%s; %d/%d complete)",
				sample.index+1, len(requests), sample.result.Status, finished, len(requests))
		case loopErr := <-loopDone:
			loopObserved = true
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, true, fmt.Errorf("kernel runtime stopped after %d/%d samples: %w",
					finished, len(requests), ctxErr)
			}
			if loopErr == nil {
				return nil, true, fmt.Errorf("kernel runtime stopped without an error after %d/%d samples",
					finished, len(requests))
			}
			return nil, true, fmt.Errorf("kernel runtime stopped after %d/%d samples: %w",
				finished, len(requests), loopErr)
		case <-ctx.Done():
			return nil, false, fmt.Errorf("waiting for mismatch samples (%d/%d complete): %w",
				finished, len(requests), ctx.Err())
		}
	}
	return results, false, nil
}

func candidateBehaviorKey(report *storedMismatchForBisect, p *prog.Prog,
	result *queue.Result) (string, error) {
	if report == nil || result == nil || p == nil {
		return "", fmt.Errorf("nil report/program/result")
	}
	type field struct {
		Kind      string          `json:"kind"`
		Path      string          `json:"path"`
		Signature string          `json:"signature,omitempty"`
		Value     json.RawMessage `json:"value"`
	}
	fields := make([]field, 0, len(report.StableDifferences))
	for _, difference := range report.StableDifferences {
		value, present, err := candidateFieldValue(&difference, p, result)
		if err != nil {
			return "", err
		}
		var encoded []byte
		if !present {
			encoded = []byte("null")
		} else {
			encoded, err = json.Marshal(value)
			if err != nil {
				return "", err
			}
		}
		canonical, err := canonicalJSON(encoded)
		if err != nil {
			return "", err
		}
		fields = append(fields, field{
			Kind: difference.Kind, Path: difference.Path, Signature: difference.Signature,
			Value: canonical,
		})
	}
	// Keep this ordering in lockstep with mismatchBehaviorKey. A candidate
	// represents one kernel revision and is compared to one runtime projection.
	for i := range fields {
		for j := i + 1; j < len(fields); j++ {
			if fields[j].Kind < fields[i].Kind ||
				fields[j].Kind == fields[i].Kind && fields[j].Path < fields[i].Path ||
				fields[j].Kind == fields[i].Kind && fields[j].Path == fields[i].Path &&
					fields[j].Signature < fields[i].Signature {
				fields[i], fields[j] = fields[j], fields[i]
			}
		}
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	digest := sha256Bytes(data)
	return digest, nil
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func candidateFieldValue(difference *storedMismatchDifference, p *prog.Prog,
	result *queue.Result) (value any, present bool, err error) {
	if difference == nil {
		return nil, false, fmt.Errorf("nil stable difference")
	}
	if p == nil || result == nil {
		return nil, false, fmt.Errorf("nil program/result")
	}
	if difference.Kind == "output" {
		return nil, false, fmt.Errorf("output differences are not yet executable by syz-bisect")
	}
	index := difference.CallIndex
	if index == nil {
		index = parseCallIndex(difference.Path)
	}
	call := (*flatrpc.CallInfo)(nil)
	if index != nil && result.Info != nil && *index >= 0 && *index < len(result.Info.Calls) {
		call = result.Info.Calls[*index]
	}
	callState := func() string {
		if call == nil || call.Flags&flatrpc.CallFlagExecuted == 0 {
			return "not_executed"
		}
		if call.Flags&flatrpc.CallFlagFinished == 0 {
			return "started_but_unfinished"
		}
		if call.Error != 0 {
			return "finished_error"
		}
		return "finished_ok"
	}
	switch difference.Kind {
	case "status":
		return result.Status, true, nil
	case "request_error":
		if result.Err == nil {
			return "", true, nil
		}
		return result.Err.Error(), true, nil
	case "call_count":
		if result.Info == nil {
			return 0, true, nil
		}
		return len(result.Info.Calls), true, nil
	case "call_presence":
		present := index != nil && result.Info != nil && *index >= 0 && *index < len(result.Info.Calls)
		return present, true, nil
	case "call_name":
		if index == nil || *index < 0 || *index >= len(p.Calls) {
			return "", true, nil
		}
		return p.CallName(*index), true, nil
	case "call_state":
		return callState(), true, nil
	case "errno":
		if call == nil || callState() != "finished_error" {
			return nil, false, nil
		}
		return call.Error, true, nil
	case "return_value":
		if call == nil || callState() != "finished_ok" || index == nil ||
			*index < 0 || *index >= len(p.Calls) || !call.ReturnValueValid {
			return nil, false, nil
		}
		if ret := p.Calls[*index].Meta.Ret; ret != nil {
			if _, resource := ret.(*prog.ResourceType); resource {
				return map[string]string{"resource": ret.String()}, true, nil
			}
		}
		return call.ReturnValue, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported stable difference kind %q", difference.Kind)
	}
}

func parseCallIndex(path string) *int {
	start := strings.Index(path, "calls[")
	if start == -1 {
		return nil
	}
	start += len("calls[")
	end := strings.IndexByte(path[start:], ']')
	if end == -1 {
		return nil
	}
	value, err := strconv.Atoi(path[start : start+end])
	if err != nil {
		return nil
	}
	return &value
}
