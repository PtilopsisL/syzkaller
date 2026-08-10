// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
)

func TestEnableSyscallOutputs(t *testing.T) {
	req := &queue.Request{
		ProgID: 1,
		Prog:   &prog.Prog{},
	}
	assert.True(t, EnableSyscallOutputs(req))
	assert.Equal(t, flatrpc.ExecFlagCollectOutputs,
		req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectOutputs)
	assert.False(t, EnableSyscallOutputs(req))
	assert.False(t, EnableSyscallOutputs(&queue.Request{Prog: &prog.Prog{}}))
}
