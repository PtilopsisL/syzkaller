// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

const (
	straceLogDirName = "strace-logs"
)

func (fuzzer *Fuzzer) maybeStraceProg(executor queue.Executor, req *queue.Request) {
	if req == nil || req.Prog == nil || req.ProgID == 0 || fuzzer.Config.Workdir == "" {
		return
	}
	logDir := filepath.Join(fuzzer.Config.Workdir, straceLogDirName)
	if err := osutil.MkdirAll(logDir); err != nil {
		fuzzer.Logf(0, "failed to create strace log dir: %v", err)
		return
	}
	progPath := filepath.Join(logDir, fmt.Sprintf("prog-%d.syz", req.ProgID))
	if err := os.WriteFile(progPath, req.Prog.Serialize(), 0o644); err != nil {
		fuzzer.Logf(0, "failed to write prog for %d: %v", req.ProgID, err)
	}

	if executor == nil {
		return
	}
	p := req.Prog.Clone()
	execOpts := req.ExecOpts
	progID := req.ProgID
	workdir := fuzzer.Config.Workdir

	go func() {
		fuzzer.straceLimiter <- struct{}{}
		release := func() {
			<-fuzzer.straceLimiter
		}
		if err := runProgUnderStrace(executor, workdir, progID, p, execOpts, release); err != nil {
			release()
			fuzzer.Logf(0, "strace for prog %d failed: %v", progID, err)
		}
	}()
}

func runProgUnderStrace(executor queue.Executor, workdir string, progID int64, p *prog.Prog,
	execOpts flatrpc.ExecOpts, release func()) error {
	logDir := filepath.Join(workdir, straceLogDirName)
	if err := osutil.MkdirAll(logDir); err != nil {
		return fmt.Errorf("failed to create strace log dir: %w", err)
	}
	progPath := filepath.Join(logDir, fmt.Sprintf("prog-%d.syz", progID))
	if err := os.WriteFile(progPath, p.Serialize(), 0o644); err != nil {
		log.Logf(0, "failed to write strace prog for %d: %v", progID, err)
	}

	opts, err := csourceOptionsFromExecOpts(execOpts, p.Target.OS)
	if err != nil {
		return err
	}

	src, err := csource.Write(p, opts)
	if err != nil {
		return fmt.Errorf("failed to generate C source: %w", err)
	}

	binPath, err := csource.Build(p.Target, src)
	if err != nil {
		return fmt.Errorf("failed to build strace program for %s/%s (ensure a matching cross-compiler is configured): %w",
			p.Target.OS, p.Target.Arch, err)
	}
	defer os.Remove(binPath)

	binData, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("failed to read strace binary: %w", err)
	}

	script, err := buildStraceScriptFromBinary(binData)
	if err != nil {
		return err
	}

	scriptFile, err := os.CreateTemp("", fmt.Sprintf("strace-prog-%d-*.sh", progID))
	if err != nil {
		return fmt.Errorf("failed to create strace script: %w", err)
	}
	if _, err := scriptFile.WriteString(script); err != nil {
		scriptFile.Close()
		os.Remove(scriptFile.Name())
		return fmt.Errorf("failed to write strace script: %w", err)
	}
	if err := scriptFile.Chmod(0o755); err != nil {
		scriptFile.Close()
		os.Remove(scriptFile.Name())
		return fmt.Errorf("failed to chmod strace script: %w", err)
	}
	scriptFile.Close()

	straceReq := &queue.Request{
		Type:         flatrpc.RequestTypeBinary,
		ExecOpts:     flatrpc.ExecOpts{EnvFlags: execOpts.EnvFlags, SandboxArg: execOpts.SandboxArg},
		BinaryFile:   scriptFile.Name(),
		ProgID:       progID,
		ReturnOutput: true,
		ReturnError:  true,
	}

	straceReq.OnDone(func(_ *queue.Request, res *queue.Result) bool {
		defer release()
		defer os.Remove(scriptFile.Name())

		logPath := filepath.Join(logDir, fmt.Sprintf("prog-%d.log", progID))
		var contents []byte
		if res != nil {
			contents = res.Output
			if res.Err != nil {
				contents = append(contents, []byte("\n\nstrace error: ")...)
				contents = append(contents, []byte(res.Err.Error())...)
			}
		}
		if len(contents) == 0 {
			contents = []byte("strace output is empty")
		}
		if writeErr := os.WriteFile(logPath, contents, 0o644); writeErr != nil {
			log.Logf(0, "failed to write strace log for %d: %v", progID, writeErr)
			return true
		}
		log.Logf(1, "stored strace log for prog %d at %s", progID, logPath)
		return true
	})

	executor.Submit(straceReq)
	return nil
}

func buildStraceScriptFromBinary(bin []byte) (string, error) {
	if len(bin) == 0 {
		return "", fmt.Errorf("empty strace binary")
	}

	const binMarker = "__SYZ_PROG_BINARY__"
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\nset -e\n")
	sb.WriteString("WORK=$(mktemp -d /tmp/syz-strace-XXXXXX)\n")
	sb.WriteString("BIN=\"$WORK/prog-bin\"\n")
	sb.WriteString("cleanup() { rm -rf \"$WORK\"; }\ntrap cleanup EXIT\n")
	sb.WriteString("decode_base64() {\n")
	sb.WriteString("  if command -v base64 >/dev/null 2>&1; then\n")
	sb.WriteString("    base64 -d\n")
	sb.WriteString("  elif command -v openssl >/dev/null 2>&1; then\n")
	sb.WriteString("    openssl base64 -d\n")
	sb.WriteString("  else\n")
	sb.WriteString("    echo \"base64 decoder not found\" >&2\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("  fi\n")
	sb.WriteString("}\n")
	sb.WriteString("cat >\"$BIN.b64\" <<'" + binMarker + "'\n")
	writeBase64Lines(&sb, bin)
	sb.WriteString("\n" + binMarker + "\n")
	sb.WriteString("decode_base64 <\"$BIN.b64\" >\"$BIN\"\n")
	sb.WriteString("chmod +x \"$BIN\"\n")
	sb.WriteString("rm -f \"$BIN.b64\"\n")
	sb.WriteString("exec strace -s 100 -x -f \"$BIN\"\n")

	return sb.String(), nil
}

func writeBase64Lines(sb *strings.Builder, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 76 {
		sb.WriteString(encoded[:76])
		sb.WriteString("\n")
		encoded = encoded[76:]
	}
	sb.WriteString(encoded)
}

func csourceOptionsFromExecOpts(execOpts flatrpc.ExecOpts, targetOS string) (csource.Options, error) {
	opts := csource.Options{
		Threaded:     execOpts.ExecFlags&flatrpc.ExecFlagThreaded != 0,
		Repeat:       false,
		Procs:        1,
		Slowdown:     1,
		SandboxArg:   int(execOpts.SandboxArg),
		UseTmpDir:    true,
		HandleSegv:   true,
		CallComments: true,
	}

	switch {
	case execOpts.EnvFlags&flatrpc.ExecEnvSandboxNamespace != 0:
		opts.Sandbox = "namespace"
	case execOpts.EnvFlags&flatrpc.ExecEnvSandboxAndroid != 0:
		opts.Sandbox = "android"
	case execOpts.EnvFlags&flatrpc.ExecEnvSandboxSetuid != 0:
		opts.Sandbox = "setuid"
	case execOpts.EnvFlags&flatrpc.ExecEnvSandboxNone != 0:
		opts.Sandbox = "none"
	}

	opts.NetInjection = execOpts.EnvFlags&flatrpc.ExecEnvEnableTun != 0
	opts.NetDevices = execOpts.EnvFlags&flatrpc.ExecEnvEnableNetDev != 0
	opts.NetReset = execOpts.EnvFlags&flatrpc.ExecEnvEnableNetReset != 0
	opts.Cgroups = execOpts.EnvFlags&flatrpc.ExecEnvEnableCgroups != 0
	opts.CloseFDs = execOpts.EnvFlags&flatrpc.ExecEnvEnableCloseFds != 0
	opts.DevlinkPCI = execOpts.EnvFlags&flatrpc.ExecEnvEnableDevlinkPCI != 0
	opts.VhciInjection = execOpts.EnvFlags&flatrpc.ExecEnvEnableVhciInjection != 0
	opts.Wifi = execOpts.EnvFlags&flatrpc.ExecEnvEnableWifi != 0
	opts.NicVF = execOpts.EnvFlags&flatrpc.ExecEnvEnableNicVF != 0

	if !opts.Repeat {
		opts.NetReset = false
	}

	if err := opts.Check(targetOS); err != nil {
		return csource.Options{}, err
	}
	return opts, nil
}
