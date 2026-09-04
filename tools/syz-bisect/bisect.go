// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-bisect runs bisection to find cause/fix commit for a crash.
//
// The tool is originally created to test pkg/bisect logic.
//
// In legacy crash mode the tool requires the wrapper config described by Config
// below and a directory with crash information passed in -crash. One minimized
// runtime mismatch, or all pending mismatches in a runtime-mismatches directory,
// can be bisected with a syz-manager multi-runtime config and -report. For
// compatibility, the same mismatch paths passed to -crash are also recognized;
// ordinary crash directories continue to use the legacy mode.
// If -fix flag is specified, it does fix bisection. Otherwise it does cause bisection. Also
// wanted syzkaller and kernel commits can be specified using -syzkaller_commit and
// -kernel_commit. HEAD is used if commits are not specified.
//
// The crash dir should contain the following files:
//   - repro.cprog or repro.prog: reproducer for the crash
//   - repro.opts: syzkaller reproducer options (e.g. {"procs":1,"sandbox":"none",...}) (optional)
//
// The tool stores bisection result into cause.commit or fix.commit.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/bisect"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagConfig            = flag.String("config", "", "manager or bisect config file")
	flagCrash             = flag.String("crash", "", "dir with crash info (or mismatch report directory)")
	flagReport            = flag.String("report", "", "minimized runtime mismatch report, prog directory, or runtime-mismatches directory")
	flagFix               = flag.Bool("fix", false, "search for crash fix")
	flagKernelCommit      = flag.String("kernel_commit", "", "original kernel commit")
	flagKernelCommitTitle = flag.String("kernel_commit_title", "", "original kernel commit title")
	flagSyzkallerCommit   = flag.String("syzkaller_commit", "", "original syzkaller commit")
)

type Config struct {
	Compiler string `json:"compiler"`
	// Currently either 'gcc' or 'clang'. Note that pkg/bisect requires
	// explicit plumbing for every os/compiler combination.
	CompilerType string `json:"compiler_type"`
	Make         string `json:"make"`
	// BinDir must point to a dir that contains compilers required to build
	// older versions of the kernel. For linux, it needs to include several
	// compiler versions.
	BinDir        string `json:"bin_dir"`
	Linker        string `json:"linker"`
	Ccache        string `json:"ccache"`
	KernelRepo    string `json:"kernel_repo"`
	KernelBranch  string `json:"kernel_branch"`
	SyzkallerRepo string `json:"syzkaller_repo"`
	// Directory with user-space system for building kernel images
	// (for linux that's the input to tools/create-gce-image.sh).
	Userspace string `json:"userspace"`
	// Sysctl/cmdline files used to build the image which was used to crash the kernel, e.g. see:
	// dashboard/config/upstream.sysctl
	// dashboard/config/upstream-selinux.cmdline
	Sysctl    string               `json:"sysctl"`
	Cmdline   string               `json:"cmdline"`
	CrossTree bool                 `json:"cross_tree"`
	Backports []vcs.BackportCommit `json:"backports"`

	KernelConfig         string `json:"kernel_config"`
	KernelBaselineConfig string `json:"kernel_baseline_config"`

	// Manager config that was used to obtain the crash.
	Manager json.RawMessage `json:"manager"`
}

func main() {
	flag.Parse()
	os.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
	mismatchPath := *flagReport
	if mismatchPath != "" && *flagCrash != "" {
		fmt.Fprintln(os.Stderr, "-report and -crash cannot be used together")
		os.Exit(1)
	}
	if mismatchPath == "" && looksLikeMismatchPath(*flagCrash) {
		// Keep the familiar syz-bisect invocation usable while making the new
		// mode explicit in the help text through -report.
		mismatchPath = *flagCrash
	}
	if mismatchPath != "" {
		if err := runMismatchMode(*flagConfig, mismatchPath); err != nil {
			fmt.Fprintf(os.Stderr, "mismatch bisection failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *flagCrash == "" {
		fmt.Fprintln(os.Stderr, "-report is required for runtime mismatch bisection (or use -crash for legacy crash bisection)")
		os.Exit(1)
	}
	if err := runCrashMode(); err != nil {
		fmt.Fprintf(os.Stderr, "bisection failed: %v\n", err)
		os.Exit(1)
	}
}

func runCrashMode() error {
	mycfg := new(Config)
	if err := config.LoadFile(*flagConfig, mycfg); err != nil {
		return err
	}
	mgrcfg, err := mgrconfig.LoadData(mycfg.Manager)
	if err != nil {
		return err
	}
	if mgrcfg.Workdir == "" {
		mgrcfg.Workdir, err = os.MkdirTemp("", "syz-bisect")
		if err != nil {
			return fmt.Errorf("failed to create temp dir: %w", err)
		}
		defer os.RemoveAll(mgrcfg.Workdir)
	}
	cfg := &bisect.Config{
		Trace: &debugtracer.GenericTracer{
			TraceWriter: os.Stdout,
			OutDir:      *flagCrash,
		},
		Fix:             *flagFix,
		DefaultCompiler: mycfg.Compiler,
		CompilerType:    mycfg.CompilerType,
		Make:            mycfg.Make,
		Linker:          mycfg.Linker,
		BinDir:          mycfg.BinDir,
		Ccache:          mycfg.Ccache,
		CrossTree:       mycfg.CrossTree,
		Kernel: bisect.KernelConfig{
			Repo:        mycfg.KernelRepo,
			Branch:      mycfg.KernelBranch,
			Commit:      *flagKernelCommit,
			CommitTitle: *flagKernelCommitTitle,
			Userspace:   mycfg.Userspace,
			Sysctl:      mycfg.Sysctl,
			Cmdline:     mycfg.Cmdline,
			Backports:   mycfg.Backports,
		},
		Syzkaller: bisect.SyzkallerConfig{
			Repo:   mycfg.SyzkallerRepo,
			Commit: *flagSyzkallerCommit,
		},
		Manager: mgrcfg,
	}
	loadFile("", mycfg.KernelConfig, &cfg.Kernel.Config, true)
	loadFile("", mycfg.KernelBaselineConfig, &cfg.Kernel.BaselineConfig, false)
	loadFile(*flagCrash, "repro.prog", &cfg.Repro.Syz, false)
	loadFile(*flagCrash, "repro.cprog", &cfg.Repro.C, false)
	loadFile(*flagCrash, "repro.opts", &cfg.Repro.Opts, false)

	if len(cfg.Repro.Syz) == 0 && len(cfg.Repro.C) == 0 {
		return fmt.Errorf("no repro.cprog or repro.prog found")
	}

	if cfg.Syzkaller.Commit == "" {
		cfg.Syzkaller.Commit = vcs.HEAD
	}
	if cfg.Kernel.Commit == "" {
		cfg.Kernel.Commit = vcs.HEAD
	}

	result, err := bisect.Run(cfg)
	if err != nil {
		return err
	}

	saveResultCommits(result.Commits)
	return nil
}

// runMismatchMode handles either one minimized runtime mismatch or all pending
// mismatches in an explicitly named runtime-mismatches directory. The manager
// config supplies the workdir and all runtime/kernel information. reportPath is
// deliberately required so an early debugging run cannot unexpectedly start
// bisection for every report.
func runMismatchMode(filename, reportPath string) error {
	if filename == "" {
		return fmt.Errorf("-config is required")
	}
	if reportPath == "" {
		return fmt.Errorf("-report is required")
	}
	if *flagFix || *flagKernelCommit != "" || *flagKernelCommitTitle != "" || *flagSyzkallerCommit != "" {
		return fmt.Errorf("-fix/-kernel_commit/-kernel_commit_title/-syzkaller_commit require legacy -crash mode")
	}
	cfg, err := mgrconfig.LoadFile(filename)
	if err != nil {
		return err
	}
	if !cfg.IsMultiRuntime() {
		return fmt.Errorf("manager config does not define multiple runtimes")
	}
	selection, err := loadMismatchCandidates(reportPath)
	if err != nil {
		return err
	}
	if selection.Batch {
		fmt.Fprintf(os.Stdout, "batch: found %d pending minimized mismatch(es) in %s (%d skipped, %d invalid)\n",
			len(selection.Candidates), reportPath, selection.Skipped, len(selection.Failures))
	}
	var workspace *mismatchBisectWorkspace
	if selection.Batch {
		workspace, err = prepareMismatchBatchWorkspace(filepath.Clean(reportPath))
		if err != nil {
			return fmt.Errorf("prepare shared batch workspace: %w", err)
		}
		fmt.Fprintf(os.Stdout, "batch: using shared kernel workspace %s\n", workspace.RootDir)
	}
	failures := append([]error(nil), selection.Failures...)
	for _, err := range selection.Failures {
		fmt.Fprintf(os.Stderr, "batch: candidate discovery failed: %v\n", err)
	}
	completed := 0
	for index, candidate := range selection.Candidates {
		if selection.Batch {
			fmt.Fprintf(os.Stdout, "batch: starting %d/%d (prog %d)\n",
				index+1, len(selection.Candidates), candidate.ProgID)
		}
		if err := runMismatchCandidate(candidate, cfg, workspace); err != nil {
			if !selection.Batch {
				return err
			}
			failures = append(failures, fmt.Errorf("prog %d: %w", candidate.ProgID, err))
			fmt.Fprintf(os.Stderr, "batch: prog %d failed: %v\n", candidate.ProgID, err)
			continue
		}
		completed++
	}
	if !selection.Batch {
		return nil
	}
	fmt.Fprintf(os.Stdout, "batch: completed %d, failed %d, skipped %d\n",
		completed, len(failures), selection.Skipped)
	if len(failures) != 0 {
		return fmt.Errorf("%d mismatch bisection(s) failed: %w", len(failures), errors.Join(failures...))
	}
	return nil
}

func runMismatchCandidate(candidate *mismatchCandidate, cfg *mgrconfig.Config,
	workspace *mismatchBisectWorkspace) error {
	if err := analyzeMismatchHistory(candidate, cfg); err != nil {
		return fmt.Errorf("analyze mismatch history: %w", err)
	}
	fmt.Fprintf(os.Stdout, "prog %d: runtimes %s, good %s (%s), bad %s (%s)\n",
		candidate.ProgID, candidate.History.Pattern,
		candidate.History.Good.Name, candidate.History.Good.Commit.Hash,
		candidate.History.Bad.Name, candidate.History.Bad.Commit.Hash)
	if err := bisectMismatch(candidate, cfg, workspace); err != nil {
		return err
	}
	return nil
}

func loadFile(path, file string, dst *[]byte, mandatory bool) {
	filename := filepath.Join(path, file)
	if !mandatory && !osutil.IsExist(filename) {
		return
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	*dst = data
}

func saveResultCommits(commits []*vcs.Commit) {
	var result string
	if len(commits) > 0 {
		for _, commit := range commits {
			result = result + commit.Hash + "\n"
		}
	} else if *flagFix {
		result = "the crash still happens on HEAD\n"
	} else {
		result = "the crash already happened on the oldest tested release\n"
	}

	var fileName string
	if *flagFix {
		fileName = filepath.Join(*flagCrash, "fix.commit")
	} else {
		fileName = filepath.Join(*flagCrash, "cause.commit")
	}
	osutil.WriteFile(fileName, []byte(result))
}
