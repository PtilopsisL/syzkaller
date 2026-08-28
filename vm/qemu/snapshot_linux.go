// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/osutil"
	"golang.org/x/sys/unix"
)

type snapshotTemplate struct {
	mu         sync.RWMutex
	dir        string
	image      string
	baseImage  string
	baseFormat string
	qemuImg    string
	ready      bool
}

type snapshot struct {
	template    *snapshotTemplate
	restored    bool
	ivsListener *net.UnixListener
	ivsConn     *net.UnixConn
	doorbellFD  int
	eventFD     int
	shmemFD     int
	shmem       []byte
	input       []byte
	header      *flatrpc.SnapshotHeaderT
}

func newSnapshotTemplate(workdir, baseImage, qemu string) (*snapshotTemplate, error) {
	if baseImage == "" || baseImage == "9p" {
		return nil, fmt.Errorf("qemu: shared snapshot mode requires a disk image")
	}
	absImage, err := filepath.Abs(baseImage)
	if err != nil {
		return nil, fmt.Errorf("qemu: failed to resolve snapshot base image: %w", err)
	}
	qemuImg, err := findQemuImg(qemu)
	if err != nil {
		return nil, fmt.Errorf("qemu: shared snapshot mode requires qemu-img: %w", err)
	}
	output, err := osutil.RunCmd(time.Minute, "", qemuImg, "info", "--output=json", absImage)
	if err != nil {
		return nil, fmt.Errorf("qemu: failed to inspect snapshot base image: %w", err)
	}
	var info struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return nil, fmt.Errorf("qemu: failed to parse snapshot base image info: %w", err)
	}
	if info.Format == "" {
		return nil, fmt.Errorf("qemu: snapshot base image format is empty")
	}
	dir, err := os.MkdirTemp(workdir, "snapshot-template-")
	if err != nil {
		return nil, fmt.Errorf("qemu: failed to create snapshot template directory: %w", err)
	}
	return &snapshotTemplate{
		dir:        dir,
		image:      filepath.Join(dir, "image.qcow2"),
		baseImage:  absImage,
		baseFormat: info.Format,
		qemuImg:    qemuImg,
	}, nil
}

func findQemuImg(qemu string) (string, error) {
	qemuPath, err := exec.LookPath(qemu)
	if err == nil {
		candidate := filepath.Join(filepath.Dir(qemuPath), "qemu-img")
		if osutil.IsExist(candidate) {
			return candidate, nil
		}
	}
	return exec.LookPath("qemu-img")
}

func (template *snapshotTemplate) prepare(inst *instance) error {
	image := filepath.Join(inst.workdir, "snapshot-image.qcow2")
	template.mu.RLock()
	defer template.mu.RUnlock()
	if template.ready {
		if err := cloneSnapshotImage(template.image, image); err != nil {
			return fmt.Errorf("qemu: failed to clone shared snapshot: %w", err)
		}
		inst.snapshot.restored = true
	} else {
		if _, err := osutil.RunCmd(time.Minute, "", template.qemuImg,
			"create", "-f", "qcow2", "-F", template.baseFormat,
			"-b", template.baseImage, image); err != nil {
			return fmt.Errorf("qemu: failed to create private snapshot image: %w", err)
		}
	}
	inst.image = image
	inst.imageFormat = "qcow2"
	return nil
}

func (template *snapshotTemplate) publish(image string) error {
	template.mu.Lock()
	defer template.mu.Unlock()
	if template.ready {
		return nil
	}
	if err := cloneSnapshotImage(image, template.image); err != nil {
		return fmt.Errorf("qemu: failed to export shared snapshot: %w", err)
	}
	template.ready = true
	return nil
}

func (template *snapshotTemplate) Close() error {
	template.mu.Lock()
	defer template.mu.Unlock()
	return os.RemoveAll(template.dir)
}

func cloneSnapshotImage(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	stat, err := srcFile.Stat()
	if err != nil {
		return err
	}
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stat.Mode()&os.ModePerm)
	if err != nil {
		return err
	}
	cloneErr := unix.IoctlFileClone(int(dstFile.Fd()), int(srcFile.Fd()))
	closeErr := dstFile.Close()
	if cloneErr == nil && closeErr == nil {
		return nil
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return osutil.CopyFile(src, dst)
}

func (inst *instance) SnapshotReady() bool {
	return inst.snapshot != nil && inst.snapshot.restored
}

func (inst *instance) snapshotRestoreArgs() []string {
	if !inst.snapshot.restored {
		return nil
	}
	// Loading the snapshot from the command line is too early for a new QEMU
	// process. The destination does not have x-ignore-shared enabled yet, and
	// firmware has not assigned GPAs to the ivshmem PCI BARs. Start paused and
	// restore explicitly after both parts of the device setup are complete.
	return []string{"-S"}
}

type qmpPCIBus struct {
	Devices []qmpPCIDevice `json:"devices"`
}

type qmpPCIID struct {
	Vendor int `json:"vendor"`
	Device int `json:"device"`
}

type qmpPCIRegion struct {
	Address int64 `json:"address"`
	Size    int64 `json:"size"`
}

type qmpPCIDevice struct {
	ID      qmpPCIID       `json:"id"`
	Regions []qmpPCIRegion `json:"regions"`
	Bridge  *struct {
		Devices []qmpPCIDevice `json:"devices"`
	} `json:"pci_bridge,omitempty"`
}

func snapshotPCIBarsReady(buses []qmpPCIBus) bool {
	var shmem, doorbell bool
	var inspect func([]qmpPCIDevice)
	inspect = func(devices []qmpPCIDevice) {
		for _, dev := range devices {
			// Both ivshmem-plain and ivshmem-doorbell use this PCI ID.
			if dev.ID.Vendor == 0x1af4 && dev.ID.Device == 0x1110 {
				for _, region := range dev.Regions {
					if region.Address <= 0 {
						continue
					}
					switch region.Size {
					case int64(flatrpc.ConstSnapshotShmemSize):
						shmem = true
					case int64(flatrpc.ConstSnapshotDoorbellSize):
						doorbell = true
					}
				}
			}
			if dev.Bridge != nil {
				inspect(dev.Bridge.Devices)
			}
		}
	}
	for _, bus := range buses {
		inspect(bus.Devices)
	}
	return shmem && doorbell
}

func (inst *instance) snapshotWaitPCIBars(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		resp, err := inst.qmp(&qmpCommand{Execute: "query-pci"})
		if err != nil {
			return fmt.Errorf("qemu: failed to query PCI devices: %w", err)
		}
		data, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("qemu: failed to marshal PCI information: %w", err)
		}
		var buses []qmpPCIBus
		if err := json.Unmarshal(data, &buses); err != nil {
			return fmt.Errorf("qemu: failed to parse PCI information: %w", err)
		}
		if snapshotPCIBarsReady(buses) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("qemu: ivshmem PCI BARs were not assigned within %v", timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (inst *instance) snapshotHMP(cmd string) error {
	output, err := inst.hmp(cmd, 0)
	if err != nil {
		return err
	}
	return snapshotHMPOutputError(cmd, output)
}

func snapshotHMPOutputError(cmd, output string) error {
	// HMP reports some loadvm failures as command output rather than a QMP
	// error. All commands used during restore are silent on success.
	if output = strings.TrimSpace(output); output != "" {
		return fmt.Errorf("qemu hmp command %q failed:\n%s", cmd, output)
	}
	return nil
}

func (inst *instance) snapshotRestore() error {
	// Let firmware assign the PCI BARs. The saved shared RAM block is keyed by
	// its guest physical address, so loadvm rejects an unassigned destination
	// BAR (GPA 0) even when x-ignore-shared is enabled.
	if err := inst.snapshotHMP("cont"); err != nil {
		return err
	}
	if err := inst.snapshotWaitPCIBars(10 * time.Second * inst.timeouts.Scale); err != nil {
		return err
	}
	if err := inst.snapshotHMP("stop"); err != nil {
		return err
	}
	// The snapshot was saved with this capability enabled. A new QEMU process
	// starts with it disabled and must match the saved migration configuration
	// before loadvm.
	if err := inst.snapshotHMP("migrate_set_capability x-ignore-shared on"); err != nil {
		return err
	}
	inst.header.UpdateState(flatrpc.SnapshotStateSnapshotted)
	if err := inst.snapshotHMP("loadvm syz"); err != nil {
		return err
	}
	if err := inst.snapshotHMP("cont"); err != nil {
		return err
	}
	if !inst.waitSnapshotStateChange(flatrpc.SnapshotStateSnapshotted, time.Minute) {
		return fmt.Errorf("restored snapshot executor did not start")
	}
	if state := inst.header.LoadState(); state != flatrpc.SnapshotStateExecuted {
		return fmt.Errorf("restored snapshot executor entered unexpected state %v", state)
	}
	return nil
}

func (inst *instance) snapshotClose() {
	if inst.ivsListener != nil {
		inst.ivsListener.Close()
	}
	if inst.ivsConn != nil {
		inst.ivsConn.Close()
	}
	if inst.doorbellFD != 0 {
		syscall.Close(inst.doorbellFD)
	}
	if inst.eventFD != 0 {
		syscall.Close(inst.eventFD)
	}
	if inst.shmemFD != 0 {
		syscall.Close(inst.shmemFD)
	}
	if inst.shmem != nil {
		syscall.Munmap(inst.shmem)
	}
}

func (inst *instance) snapshotEnable() ([]string, error) {
	// We use ivshmem device (Inter-VM Shared Memory) for communication with the VM,
	// it allows to have a shared memory region directly accessible by both host and target:
	// https://www.qemu.org/docs/master/system/devices/ivshmem.html
	//
	// The shared memory region is not restored as part of snapshot restore since we set:
	//	migrate_set_capability x-ignore-shared on
	// This allows to write a new input into ivshmem before each restore.
	//
	// We also use doorbell (interrupt) capability of ivshmem to notify host about
	// program execution completion. Doorbell also allows to send interrupts in the other direction
	// (from host to target), but we don't need/use this since we arrange things such that
	// snapshot restore serves as a signal to execute new input.
	//
	// Ideally we use a single ivshmem device for both purposes (shmem+doorbell).
	// But unfortunately it seems that the doorbell device is always restored on snapshot restore
	// (at least I did not find a way to make it not restored, maybe can be solved with qemu change).
	// So we use 2 separate devices for these purposes.
	shmemFD, err := unix.MemfdCreate("syz-qemu-shmem", 0)
	if err != nil {
		return nil, fmt.Errorf("qemu: memfd_create failed: %w", err)
	}
	inst.shmemFD = shmemFD
	if err := syscall.Ftruncate(shmemFD, int64(flatrpc.ConstSnapshotShmemSize)); err != nil {
		return nil, fmt.Errorf("qemu: ftruncate failed: %w", err)
	}
	shmem, err := syscall.Mmap(shmemFD, 0, int(flatrpc.ConstSnapshotShmemSize),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("qemu: shmem mmap failed: %w", err)
	}
	inst.shmem = shmem
	inst.input = shmem[:flatrpc.ConstMaxInputSize:flatrpc.ConstMaxInputSize]
	inst.header = (*flatrpc.SnapshotHeaderT)(unsafe.Pointer(&shmem[flatrpc.ConstMaxInputSize]))
	shmemFile := fmt.Sprintf("/proc/%v/fd/%v", syscall.Getpid(), shmemFD)

	doorbellFD, err := unix.MemfdCreate("syz-qemu-doorbell", 0)
	if err != nil {
		return nil, fmt.Errorf("qemu: memfd_create failed: %w", err)
	}
	if err := syscall.Ftruncate(doorbellFD, int64(flatrpc.ConstSnapshotDoorbellSize)); err != nil {
		return nil, fmt.Errorf("qemu: ftruncate failed: %w", err)
	}
	inst.doorbellFD = doorbellFD

	eventFD, err := unix.Eventfd(0, unix.EFD_SEMAPHORE)
	if err != nil {
		return nil, fmt.Errorf("qemu: eventfd failed: %w", err)
	}
	inst.eventFD = eventFD

	// UNIX domain socket paths are limited to ~108 characters.
	// Prefer a relative path if it is shorter than the absolute path to avoid exceeding the limit.
	sockPath := filepath.Join(inst.workdir, "ivs.sock")
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, sockPath); err == nil && len(rel) < len(sockPath) {
			sockPath = rel
		}
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("qemu: unix listen on %v failed: %w", sockPath, err)
	}
	inst.ivsListener = ln

	return []string{
		// migratable=on is required to take snapshots.
		// tsc=off disables RDTSC timestamp counter, it's not virtualized/restored as part of snapshots,
		// so the target kernel sees a large jump in time and always declares TSC as unstable after restore.
		"-cpu", "host,migratable=on,tsc=off",
		"-chardev", fmt.Sprintf("socket,path=%v,id=snapshot-doorbell", sockPath),
		"-device", "ivshmem-doorbell,master=on,vectors=1,chardev=snapshot-doorbell",
		"-device", "ivshmem-plain,master=on,memdev=snapshot-shmem",
		"-object", fmt.Sprintf("memory-backend-file,size=%v,share=on,discard-data=on,id=snapshot-shmem,mem-path=%v",
			uint64(flatrpc.ConstSnapshotShmemSize), shmemFile),
	}, nil
}

func (inst *instance) snapshotHandshake() error {
	// ivshmem-doorbell expects an external server that communicates via a unix socket.
	// The protocol is not documented, for details see:
	// https://github.com/qemu/qemu/blob/master/hw/misc/ivshmem.c
	// https://github.com/qemu/qemu/blob/master/contrib/ivshmem-server/ivshmem-server.c
	conn, err := inst.ivsListener.AcceptUnix()
	if err != nil {
		return fmt.Errorf("qemu: unix accept failed: %w", err)
	}
	inst.ivsListener.Close()
	inst.ivsListener = nil
	inst.ivsConn = conn

	msg := make([]byte, 8)
	// Send protocol version 0.
	binary.LittleEndian.PutUint64(msg, 0)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("qemu: ivs conn write failed: %w", err)
	}
	// Send VM id 0.
	binary.LittleEndian.PutUint64(msg, 0)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("qemu: ivs conn write failed: %w", err)
	}
	// Send shared memory file FD.
	binary.LittleEndian.PutUint64(msg, ^uint64(0))
	rights := syscall.UnixRights(inst.doorbellFD)
	if _, _, err := conn.WriteMsgUnix(msg, rights, nil); err != nil {
		return fmt.Errorf("qemu: ivs conn sendmsg failed: %w", err)
	}
	// Send event FD for VM 1 interrupt vector 0.
	binary.LittleEndian.PutUint64(msg, 1)
	rights = syscall.UnixRights(inst.eventFD)
	if _, _, err := conn.WriteMsgUnix(msg, rights, nil); err != nil {
		return fmt.Errorf("qemu: ivs conn sendmsg failed: %w", err)
	}
	return nil
}

const minErrOutputWait = time.Second

func (inst *instance) SetupSnapshot(input []byte) error {
	copy(inst.input, input)
	// Tell executor that we are ready to snapshot and wait for an ack.
	inst.header.UpdateState(flatrpc.SnapshotStateHandshake)
	if !inst.waitSnapshotStateChange(flatrpc.SnapshotStateHandshake, 10*time.Minute) {
		return fmt.Errorf("executor does not start snapshot handshake\n%s", inst.readOutput(minErrOutputWait))
	}
	if _, err := inst.hmp("migrate_set_capability x-ignore-shared on", 0); err != nil {
		return err
	}
	if _, err := inst.hmp("savevm syz", 0); err != nil {
		return err
	}
	if inst.debug {
		inst.hmp("info snapshots", 0) // this prints size of the snapshot
	}
	inst.header.UpdateState(flatrpc.SnapshotStateSnapshotted)
	if !inst.waitSnapshotStateChange(flatrpc.SnapshotStateSnapshotted, time.Minute) {
		return fmt.Errorf("executor has not confirmed snapshot handshake\n%s", inst.readOutput(minErrOutputWait))
	}
	// The template image must not change while it is being cloned. This VM is
	// discarded after publishing, so leave it paused until Close kills QEMU.
	if _, err := inst.hmp("stop", 0); err != nil {
		return err
	}
	if err := inst.snapshot.template.publish(inst.image); err != nil {
		return err
	}
	return nil
}

func (inst *instance) RunSnapshot(timeout time.Duration, input []byte) (result, output []byte, err error) {
	copy(inst.input, input)
	inst.header.OutputOffset = 0
	inst.header.OutputSize = 0
	inst.header.UpdateState(flatrpc.SnapshotStateExecute)
	if _, err := inst.hmp("loadvm syz", 0); err != nil {
		return nil, nil, fmt.Errorf("%w\n%s", err, inst.readOutput(minErrOutputWait))
	}
	inst.waitSnapshotStateChange(flatrpc.SnapshotStateExecute, timeout)
	resStart := int(flatrpc.ConstMaxInputSize) + int(atomic.LoadUint32(&inst.header.OutputOffset))
	resEnd := resStart + int(atomic.LoadUint32(&inst.header.OutputSize))
	var res []byte
	if resEnd <= len(inst.shmem) {
		res = inst.shmem[resStart:resEnd:resEnd]
	}
	output = inst.readOutput(0)
	return res, output, nil
}

func (inst *instance) waitSnapshotStateChange(state flatrpc.SnapshotState, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	timeoutMs := int(timeout / time.Millisecond)
	fds := []unix.PollFd{{
		Fd:     int32(inst.eventFD),
		Events: unix.POLLIN,
	}}
	for {
		if n, _ := unix.Poll(fds, timeoutMs); n == 1 {
			var buf [8]byte
			syscall.Read(inst.eventFD, buf[:])
		}
		if inst.header.LoadState() != state {
			return true
		}
		remain := time.Until(deadline)
		if remain < time.Millisecond {
			return false
		}
		timeoutMs = int(remain / time.Millisecond)
	}
}

func (inst *instance) readOutput(minTotalWait time.Duration) []byte {
	var output []byte
	// If output channel has overflown, then wait for more output from the merger goroutine.
	wait := cap(inst.merger.Output)
	start := time.Now()
	for {
		select {
		case out := <-inst.merger.Output:
			output = append(output, out.Data...)
			wait--
		default:
			if wait > 0 {
				if time.Since(start) < minTotalWait {
					time.Sleep(5 * time.Millisecond)
					continue
				}
				return output
			}
			// After the first overflow we wait after every read because the goroutine
			// may be running and sending more output to the channel concurrently.
			wait = 1
			time.Sleep(10 * time.Millisecond)
		}
	}
}
