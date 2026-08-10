// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutputCaptureSkipsPadding(t *testing.T) {
	target, _, _ := initTest(t)
	var padding Type
	ForeachType(target.Syscalls, func(typ Type, _ *TypeCtx) {
		if padding == nil && IsPad(typ) {
			padding = typ
		}
	})
	require.NotNil(t, padding)
	assert.False(t, hasDirectOutputArg(padding.DefaultArg(DirOut)))
}
