// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package qemu

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotTemplateCreatesPrivateOverlay(t *testing.T) {
	qemuImg, err := exec.LookPath("qemu-img")
	if err != nil {
		t.Skip("qemu-img is not installed")
	}
	dir := t.TempDir()
	baseImage := filepath.Join(dir, "base.raw")
	base, err := os.Create(baseImage)
	require.NoError(t, err)
	require.NoError(t, base.Truncate(1<<20))
	require.NoError(t, base.Close())
	template, err := newSnapshotTemplate(dir, baseImage, qemuImg)
	require.NoError(t, err)
	defer template.Close()

	inst := &instance{
		workdir: filepath.Join(dir, "instance"),
		snapshot: &snapshot{
			template: template,
		},
	}
	require.NoError(t, os.MkdirAll(inst.workdir, 0o755))
	require.NoError(t, template.prepare(inst))
	assert.False(t, inst.snapshot.restored)
	output, err := osutil.RunCmd(time.Minute, "", qemuImg, "info", "--output=json", inst.image)
	require.NoError(t, err)
	var info struct {
		Format          string `json:"format"`
		BackingFilename string `json:"backing-filename"`
	}
	require.NoError(t, json.Unmarshal(output, &info))
	assert.Equal(t, "qcow2", info.Format)
	assert.Equal(t, baseImage, info.BackingFilename)
}

func TestSnapshotTemplateClonesPrivateImage(t *testing.T) {
	dir := t.TempDir()
	builderImage := filepath.Join(dir, "builder.qcow2")
	require.NoError(t, os.WriteFile(builderImage, []byte("shared snapshot"), 0o600))
	template := &snapshotTemplate{
		dir:   filepath.Join(dir, "template"),
		image: filepath.Join(dir, "template", "image.qcow2"),
	}
	require.NoError(t, os.MkdirAll(template.dir, 0o755))
	require.NoError(t, template.publish(builderImage))

	inst := &instance{
		workdir: filepath.Join(dir, "instance"),
		snapshot: &snapshot{
			template: template,
		},
	}
	require.NoError(t, os.MkdirAll(inst.workdir, 0o755))
	require.NoError(t, template.prepare(inst))
	assert.True(t, inst.snapshot.restored)
	assert.Equal(t, "qcow2", inst.imageFormat)
	data, err := os.ReadFile(inst.image)
	require.NoError(t, err)
	assert.Equal(t, []byte("shared snapshot"), data)

	require.NoError(t, os.WriteFile(inst.image, []byte("private changes"), 0o600))
	data, err = os.ReadFile(template.image)
	require.NoError(t, err)
	assert.Equal(t, []byte("shared snapshot"), data)
}

func TestSnapshotRestoreArgs(t *testing.T) {
	inst := &instance{snapshot: &snapshot{}}
	assert.Empty(t, inst.snapshotRestoreArgs())
	inst.snapshot.restored = true
	assert.Equal(t, []string{"-S"}, inst.snapshotRestoreArgs())
}

func TestSnapshotPCIBarsReady(t *testing.T) {
	newDevice := func(size, address int64) qmpPCIDevice {
		var dev qmpPCIDevice
		dev.ID.Vendor = 0x1af4
		dev.ID.Device = 0x1110
		dev.Regions = append(dev.Regions, qmpPCIRegion{Address: address, Size: size})
		return dev
	}

	shmem := newDevice(int64(flatrpc.ConstSnapshotShmemSize), 0xfa000000)
	doorbell := newDevice(int64(flatrpc.ConstSnapshotDoorbellSize), 0xfd000000)
	assert.False(t, snapshotPCIBarsReady(nil))
	assert.False(t, snapshotPCIBarsReady([]qmpPCIBus{{Devices: []qmpPCIDevice{shmem}}}))
	doorbell.Regions[0].Address = -1
	assert.False(t, snapshotPCIBarsReady([]qmpPCIBus{{Devices: []qmpPCIDevice{shmem, doorbell}}}))
	doorbell.Regions[0].Address = 0xfd000000
	assert.True(t, snapshotPCIBarsReady([]qmpPCIBus{{Devices: []qmpPCIDevice{shmem, doorbell}}}))
}

func TestSnapshotHMPOutputError(t *testing.T) {
	assert.NoError(t, snapshotHMPOutputError("loadvm syz", "\r\n"))
	err := snapshotHMPOutputError("loadvm syz",
		"Mismatched GPAs for block snapshot-shmem 4194304000!= 0\r\n"+
			"Error: error while loading state for device 'ram'")
	assert.ErrorContains(t, err, "Mismatched GPAs")
}
