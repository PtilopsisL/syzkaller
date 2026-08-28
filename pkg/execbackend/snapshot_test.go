// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotEnvFlagsDropSyscallTrace(t *testing.T) {
	flags := flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSyscallTrace
	assert.Equal(t, flatrpc.ExecEnvSandboxNone, snapshotEnvFlags(flags))
}

func TestSharedSnapshotHasSingleBuilder(t *testing.T) {
	serv := &snapshotServer{templateChanged: make(chan struct{})}
	started := make(chan struct{})
	finish := make(chan struct{})
	var setupCalls atomic.Int32
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- serv.ensureSharedSnapshot(t.Context(), flatrpc.ExecEnvSandboxNone, func() error {
			setupCalls.Add(1)
			close(started)
			<-finish
			return nil
		})
	}()
	<-started

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- serv.ensureSharedSnapshot(t.Context(), flatrpc.ExecEnvSandboxSetuid, func() error {
			setupCalls.Add(1)
			return nil
		})
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("second setup returned before the builder completed: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(finish)
	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
	assert.EqualValues(t, 1, setupCalls.Load())
	flags, err := serv.waitSharedSnapshot(t.Context())
	require.NoError(t, err)
	assert.Equal(t, flatrpc.ExecEnvSandboxNone, flags)
}

func TestSharedSnapshotRetriesFailedBuilder(t *testing.T) {
	serv := &snapshotServer{templateChanged: make(chan struct{})}
	wantErr := errors.New("setup failed")
	err := serv.ensureSharedSnapshot(t.Context(), flatrpc.ExecEnvSandboxNone, func() error {
		return wantErr
	})
	assert.ErrorIs(t, err, wantErr)

	require.NoError(t, serv.ensureSharedSnapshot(context.Background(), flatrpc.ExecEnvSandboxSetuid,
		func() error { return nil }))
	flags, err := serv.waitSharedSnapshot(t.Context())
	require.NoError(t, err)
	assert.Equal(t, flatrpc.ExecEnvSandboxSetuid, flags)
}
