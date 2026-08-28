// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

type SnapshotConfig struct {
	*mgrconfig.Config
	Stats rpcserver.Stats
}

type snapshotServer struct {
	Server
	cfg              SnapshotConfig
	source           *queue.DynamicSourceCtl
	dist             *queue.Distributor
	bootDone         chan struct{}
	bootOnce         sync.Once
	templateMu       sync.Mutex
	templateBuilding bool
	templateReady    bool
	templateChanged  chan struct{}
	templateEnvFlags flatrpc.ExecEnv
}

func NewSnapshotBackend(base Server, cfg SnapshotConfig) Server {
	source := queue.DynamicSource(queue.Plain())
	return &snapshotServer{
		Server:          base,
		cfg:             cfg,
		source:          source,
		dist:            queue.Distribute(queue.Retry(source)),
		bootDone:        make(chan struct{}),
		templateChanged: make(chan struct{}),
	}
}

func (serv *snapshotServer) SetSource(source queue.Source) {
	serv.source.Store(source)
	serv.bootOnce.Do(func() {
		close(serv.bootDone)
	})
	serv.Server.Close()
}

func (serv *snapshotServer) RunRequests(ctx context.Context, inst *vm.Instance,
	reporter *report.Reporter, updInfo dispatcher.UpdateInfo) (
	[]*report.Report, error) {
	select {
	case <-serv.bootDone:
		// Machine check has already completed. Proceed to snapshot mode.
	default:
		// Machine check has not completed yet. We must boot the VM normally using the base RPC server
		// so that it connects, exchanges capabilities, and triggers MachineChecked.
		bootCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-bootCtx.Done():
			case <-serv.bootDone:
				cancel()
			}
		}()
		reps, err := serv.Server.RunRequests(bootCtx, inst, reporter, updInfo)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		return reps, err
	}

	builder := flatbuffers.NewBuilder(0)
	var envFlags flatrpc.ExecEnv
	restored := inst.SnapshotReady()
	if restored {
		var err error
		envFlags, err = serv.waitSharedSnapshot(ctx)
		if err != nil {
			return nil, err
		}
		updInfo(func(info *dispatcher.Info) {
			info.Status = "snapshot fuzzing"
		})
	} else {
		updInfo(func(info *dispatcher.Info) {
			info.Status = "building shared snapshot"
		})
		executorBin, err := inst.Copy(serv.cfg.ExecutorBin)
		if err != nil {
			return nil, err
		}

		// All network connections (including ssh) will break once we start restoring snapshots.
		// So we start a background process and log to /dev/kmsg.
		cmd := fmt.Sprintf("nohup %v exec snapshot 1>/dev/null 2>/dev/kmsg </dev/null &", executorBin)
		ctxTimeout, cancel := context.WithTimeout(ctx, time.Hour)
		defer cancel()
		if _, _, err := inst.Run(ctxTimeout, reporter, cmd); err != nil {
			return nil, err
		}
	}

	if serv.cfg.Stats.StatNumFuzzing != nil {
		serv.cfg.Stats.StatNumFuzzing.Add(1)
		defer serv.cfg.Stats.StatNumFuzzing.Add(-1)
	}

	// Poll for execution requests. When no request is available (req == nil),
	// sleep and retry instead of returning, because returning from RunRequests
	// signals to the VM dispatcher that the instance lifecycle has ended and
	// would cause the VM to be restarted.
	first := !restored
	for ctx.Err() == nil {
		req := serv.dist.Next(inst.Index())
		if req == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		req.ExecOpts.EnvFlags = snapshotEnvFlags(req.ExecOpts.EnvFlags)
		if first {
			envFlags = req.ExecOpts.EnvFlags
			err := serv.ensureSharedSnapshot(ctx, envFlags, func() error {
				return serv.snapshotSetup(inst, builder, envFlags)
			})
			if err != nil {
				status := queue.Crashed
				if errors.Is(err, context.Canceled) {
					status = queue.Restarted
				}
				req.Done(&queue.Result{Status: status})
				return nil, err
			}
			// Setup/publishing leaves the builder paused, and any other fresh VM
			// predates the template. Restart all of them and retry their requests
			// on private clones of the same exported snapshot.
			req.Done(&queue.Result{Status: queue.Restarted})
			return nil, nil
		}
		if envFlags != req.ExecOpts.EnvFlags {
			panic(fmt.Sprintf("request env flags has changed: 0x%x -> 0x%x",
				envFlags, req.ExecOpts.EnvFlags))
		}
		if serv.cfg.Stats.StatExecs != nil {
			serv.cfg.Stats.StatExecs.Add(1)
		}

		res, output, err := serv.snapshotRun(inst, builder, req)
		if err != nil {
			req.Done(&queue.Result{
				Executor: queue.ExecutorID{VM: inst.Index()},
				Status:   queue.Crashed,
			})
			return nil, err
		}

		if reporter.ContainsCrash(output) {
			res.Status = queue.Crashed
			rep := reporter.Parse(output)
			if rep == nil {
				rep = &report.Report{
					Title:  "unknown crash",
					Output: output,
				}
			}
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "program:\n%s\n", req.Prog.Serialize())
			buf.Write(rep.Output)
			rep.Output = buf.Bytes()

			req.Done(res)
			return []*report.Report{rep}, nil
		}

		req.Done(res)
	}
	return nil, nil
}

func (serv *snapshotServer) ensureSharedSnapshot(ctx context.Context, env flatrpc.ExecEnv,
	setup func() error) error {
	for {
		serv.templateMu.Lock()
		if serv.templateReady {
			serv.templateMu.Unlock()
			return nil
		}
		if !serv.templateBuilding {
			serv.templateBuilding = true
			changed := serv.templateChanged
			serv.templateMu.Unlock()

			err := setup()
			serv.templateMu.Lock()
			serv.templateBuilding = false
			if err == nil {
				serv.templateReady = true
				serv.templateEnvFlags = env
			}
			close(changed)
			if err != nil {
				serv.templateChanged = make(chan struct{})
			}
			serv.templateMu.Unlock()
			return err
		}
		changed := serv.templateChanged
		serv.templateMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (serv *snapshotServer) waitSharedSnapshot(ctx context.Context) (flatrpc.ExecEnv, error) {
	for {
		serv.templateMu.Lock()
		if serv.templateReady {
			env := serv.templateEnvFlags
			serv.templateMu.Unlock()
			return env, nil
		}
		changed := serv.templateChanged
		serv.templateMu.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-changed:
		}
	}
}

func snapshotEnvFlags(flags flatrpc.ExecEnv) flatrpc.ExecEnv {
	// Snapshot executor does not initialize syscall trace buffers, and environment flags
	// are fixed when the snapshot is created rather than supplied with each request.
	return flags &^ flatrpc.ExecEnvSyscallTrace
}

func (serv *snapshotServer) snapshotSetup(inst *vm.Instance, builder *flatbuffers.Builder, env flatrpc.ExecEnv) error {
	msg := flatrpc.SnapshotHandshakeT{
		CoverEdges:       serv.cfg.Experimental.CoverEdges,
		Kernel64Bit:      serv.cfg.SysTarget.PtrSize == 8,
		Slowdown:         int32(serv.cfg.Timeouts.Slowdown),
		SyscallTimeoutMs: int32(serv.cfg.Timeouts.Syscall / time.Millisecond),
		ProgramTimeoutMs: int32(serv.cfg.Timeouts.Program / time.Millisecond),
		Features:         serv.Server.Features(),
		EnvFlags:         env,
		SandboxArg:       serv.cfg.SandboxArg,
	}
	builder.Reset()
	builder.Finish(msg.Pack(builder))
	return inst.SetupSnapshot(builder.FinishedBytes())
}

func (serv *snapshotServer) snapshotRun(inst *vm.Instance, builder *flatbuffers.Builder, req *queue.Request) (
	*queue.Result, []byte, error) {
	progData, err := req.Prog.SerializeForExec()
	if err != nil {
		queue.StatExecBufferTooSmall.Add(1)
		return &queue.Result{
			Executor: queue.ExecutorID{VM: inst.Index()},
			Status:   queue.ExecFailure,
			Err:      fmt.Errorf("program serialization failed: %w", err),
		}, nil, nil
	}
	execOpts := req.EffectiveExecOpts()
	msg := flatrpc.SnapshotRequestT{
		ExecFlags: execOpts.ExecFlags,
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
		Executor: queue.ExecutorID{VM: inst.Index()},
		Status:   queue.Success,
		Info:     res.Info,
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
