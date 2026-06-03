// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
)

// EnableSyscallTrace marks logical syzlang program requests for syscall trace collection.
func EnableSyscallTrace(req *queue.Request) bool {
	if req == nil || req.Prog == nil || req.ProgID == 0 {
		return false
	}
	if req.ExecOpts.EnvFlags&flatrpc.ExecEnvSyscallTrace != 0 {
		return false
	}
	req.ExecOpts.EnvFlags |= flatrpc.ExecEnvSyscallTrace
	return true
}

func (fuzzer *Fuzzer) maybeStraceProg(req *queue.Request) bool {
	if !EnableSyscallTrace(req) {
		return false
	}
	fuzzer.straceQueue.Submit(req)
	return true
}
