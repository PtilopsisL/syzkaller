// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
)

func (fuzzer *Fuzzer) maybeStraceProg(executor queue.Executor, req *queue.Request) {
	if req == nil || req.Prog == nil || req.ProgID == 0 {
		return
	}
	req.ExecOpts.EnvFlags |= flatrpc.ExecEnvSyscallTrace
}
