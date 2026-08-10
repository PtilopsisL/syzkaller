// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/stretchr/testify/assert"
)

func TestSnapshotEnvFlagsDropSyscallTrace(t *testing.T) {
	flags := flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSyscallTrace
	assert.Equal(t, flatrpc.ExecEnvSandboxNone, snapshotEnvFlags(flags))
}
