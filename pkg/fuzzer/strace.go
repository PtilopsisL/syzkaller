// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
)

func (fuzzer *Fuzzer) maybeStraceProg(req *queue.Request) bool {
	if req == nil || req.Prog == nil || req.ProgID == 0 {
		return false
	}
	if req.ExecOpts.EnvFlags&flatrpc.ExecEnvSyscallTrace != 0 {
		return false
	}
	req.ExecOpts.EnvFlags |= flatrpc.ExecEnvSyscallTrace
	fuzzer.straceQueue.Submit(req)
	return true
}
