// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotEnvFlagsDropSyscallTrace(t *testing.T) {
	flags := flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSyscallTrace
	assert.Equal(t, flatrpc.ExecEnvSandboxNone, snapshotEnvFlags(flags))
}

func TestSnapshotExecutorEpochPerLifecycle(t *testing.T) {
	serv := &snapshotServer{}
	first := serv.newSnapshotExecutor(2)
	second := serv.newSnapshotExecutor(2)

	assert.Equal(t, 2, first.VM)
	require.NotZero(t, first.SnapshotEpoch)
	assert.Equal(t, 2, second.VM)
	assert.Greater(t, second.SnapshotEpoch, first.SnapshotEpoch)
}
