// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !linux

package qemu

import (
	"fmt"
	"time"
)

type snapshotTemplate struct{}

type snapshot struct {
	template *snapshotTemplate
	restored bool
}

var errNotImplemented = fmt.Errorf("snapshots are not implemeneted")

func newSnapshotTemplate(workdir, baseImage, qemu string) (*snapshotTemplate, error) {
	return nil, errNotImplemented
}

func (template *snapshotTemplate) prepare(inst *instance) error {
	return errNotImplemented
}

func (template *snapshotTemplate) Close() error {
	return nil
}

func (inst *instance) SnapshotReady() bool {
	return false
}

func (inst *instance) snapshotRestoreArgs() []string {
	return nil
}

func (inst *instance) snapshotRestore() error {
	return errNotImplemented
}

func (inst *instance) snapshotClose() {
}

func (inst *instance) snapshotEnable() ([]string, error) {
	return nil, errNotImplemented
}

func (inst *instance) snapshotHandshake() error {
	return errNotImplemented
}

func (inst *instance) SetupSnapshot(input []byte) error {
	return errNotImplemented
}

func (inst *instance) RunSnapshot(timeout time.Duration, input []byte) (result, output []byte, err error) {
	return nil, nil, errNotImplemented
}
