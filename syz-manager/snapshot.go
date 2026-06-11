// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

func (mgr *Manager) snapshotInstance(slot *managedRuntime, ctx context.Context,
	inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	slot.stats.StatNumFuzzing.Add(1)
	defer slot.stats.StatNumFuzzing.Add(-1)

	updInfo(func(info *dispatcher.Info) {
		info.Status = "snapshot fuzzing"
	})

	err := mgr.snapshotLoop(slot, ctx, inst)
	if err != nil {
		log.Errorf("%s: %v", slot.name, err)
	}
}

func (mgr *Manager) snapshotLoop(slot *managedRuntime, ctx context.Context, inst *vm.Instance) error {
	executor, err := inst.Copy(slot.cfg.ExecutorBin)
	if err != nil {
		return err
	}
	// All network connections (including ssh) will break once we start restoring snapshots.
	// So we start a background process and log to /dev/kmsg.
	cmd := fmt.Sprintf("nohup %v exec snapshot 1>/dev/null 2>/dev/kmsg </dev/null &", executor)
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	if _, _, err := inst.Run(ctxTimeout, slot.runtime.Reporter(), cmd); err != nil {
		return err
	}

	builder := flatbuffers.NewBuilder(0)
	var envFlags flatrpc.ExecEnv
	for first := true; ctx.Err() == nil; first = false {
		slot.stats.StatExecs.Add(1)
		req := slot.snapshotSource.Next(inst.Index())
		if req == nil {
			return nil
		}
		req.ExecOpts.EnvFlags = snapshotEnvFlags(req.ExecOpts.EnvFlags)
		if first {
			envFlags = req.ExecOpts.EnvFlags
			if err := mgr.snapshotSetup(slot, inst, builder, envFlags); err != nil {
				req.Done(&queue.Result{Status: queue.Crashed})
				return err
			}
		}
		if envFlags != req.ExecOpts.EnvFlags {
			panic(fmt.Sprintf("request env flags has changed: 0x%x -> 0x%x",
				envFlags, req.ExecOpts.EnvFlags))
		}

		res, output, err := mgr.snapshotRun(inst, builder, req)
		if err != nil {
			req.Done(&queue.Result{Status: queue.Crashed})
			return err
		}

		if slot.runtime.Reporter().ContainsCrash(output) {
			res.Status = queue.Crashed
			rep := slot.runtime.Reporter().Parse(output)
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "program:\n%s\n", req.Prog.Serialize())
			buf.Write(rep.Output)
			rep.Output = buf.Bytes()
			mgr.crashes <- &manager.Crash{
				Runtime:       slot.name,
				InstanceIndex: inst.Index(),
				Report:        rep,
			}
		}

		req.Done(res)
	}
	return nil
}

func (mgr *Manager) snapshotSetup(slot *managedRuntime, inst *vm.Instance,
	builder *flatbuffers.Builder, env flatrpc.ExecEnv) error {
	msg := flatrpc.SnapshotHandshakeT{
		CoverEdges:       slot.cfg.Experimental.CoverEdges,
		Kernel64Bit:      slot.cfg.SysTarget.PtrSize == 8,
		Slowdown:         int32(slot.cfg.Timeouts.Slowdown),
		SyscallTimeoutMs: int32(slot.cfg.Timeouts.Syscall / time.Millisecond),
		ProgramTimeoutMs: int32(slot.cfg.Timeouts.Program / time.Millisecond),
		Features:         slot.features,
		EnvFlags:         env,
		SandboxArg:       slot.cfg.SandboxArg,
	}
	builder.Reset()
	builder.Finish(msg.Pack(builder))
	return inst.SetupSnapshot(builder.FinishedBytes())
}

func snapshotEnvFlags(flags flatrpc.ExecEnv) flatrpc.ExecEnv {
	// Snapshot executor does not initialize syscall trace buffers, and environment flags
	// are fixed when the snapshot is created rather than supplied with each request.
	return flags &^ flatrpc.ExecEnvSyscallTrace
}

func (mgr *Manager) snapshotRun(inst *vm.Instance, builder *flatbuffers.Builder,
	req *queue.Request) (*queue.Result, []byte, error) {
	progData, err := req.Prog.SerializeForExec()
	if err != nil {
		queue.StatExecBufferTooSmall.Add(1)
		return &queue.Result{
			Status: queue.ExecFailure,
			Err:    fmt.Errorf("program serialization failed: %w", err),
		}, nil, nil
	}
	msg := flatrpc.SnapshotRequestT{
		ExecFlags: req.ExecOpts.ExecFlags,
		NumCalls:  int32(len(req.Prog.Calls)),
		ProgData:  progData,
	}
	for _, call := range req.ReturnAllSignal {
		if call < 0 {
			msg.AllExtraSignal = true
		} else {
			msg.AllCallSignal |= 1 << call
		}
	}
	builder.Reset()
	builder.Finish(msg.Pack(builder))

	start := time.Now()
	resData, output, err := inst.RunSnapshot(builder.FinishedBytes())
	if err != nil {
		return nil, nil, err
	}
	elapsed := time.Since(start)

	res := parseExecResult(resData)
	if res.Info != nil {
		res.Info.Elapsed = uint64(elapsed)
		for len(res.Info.Calls) < len(req.Prog.Calls) {
			res.Info.Calls = append(res.Info.Calls, &flatrpc.CallInfo{
				Error: 999,
			})
		}
		res.Info.Calls = res.Info.Calls[:len(req.Prog.Calls)]
		if len(res.Info.ExtraRaw) != 0 {
			res.Info.Extra = res.Info.ExtraRaw[0]
			for _, info := range res.Info.ExtraRaw[1:] {
				res.Info.Extra.Cover = append(res.Info.Extra.Cover, info.Cover...)
				res.Info.Extra.Signal = append(res.Info.Extra.Signal, info.Signal...)
			}
			res.Info.ExtraRaw = nil
		}
	}

	ret := &queue.Result{
		Status: queue.Success,
		Info:   res.Info,
	}
	if res.Error != "" {
		ret.Status = queue.ExecFailure
		ret.Err = errors.New(res.Error)
	}
	if req.ReturnOutput {
		ret.Output = output
	}
	return ret, output, nil
}

func parseExecResult(data []byte) *flatrpc.ExecResult {
	if len(data) < flatbuffers.SizeUint32 {
		return &flatrpc.ExecResult{
			Error: "the buffer is too small",
		}
	}
	raw, err := flatrpc.Parse[*flatrpc.ExecutorMessageRaw](data[flatbuffers.SizeUint32:])
	if err != nil {
		// Don't consider result parsing error as an infrastructure error,
		// it's just the test program corrupted memory.
		return &flatrpc.ExecResult{
			Error: err.Error(),
		}
	}
	res, ok := raw.Msg.Value.(*flatrpc.ExecResult)
	if !ok {
		return &flatrpc.ExecResult{
			Error: "result is not ExecResult",
		}
	}
	return res
}
