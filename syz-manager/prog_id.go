// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

const (
	progIDStateFileName    = "runtime-prog-id.json"
	progIDStateFileVersion = 1
	progIDReserveBatch     = 4096
	maxProgID              = int64(1<<63 - 1)
)

type progIDStateFile struct {
	Version         int   `json:"version"`
	ReservedThrough int64 `json:"reserved_through"`
}

func progIDStatePath(workdir string) string {
	if workdir == "" {
		return ""
	}
	return filepath.Join(workdir, progIDStateFileName)
}

func loadProgIDState(path string) (int64, error) {
	if path == "" {
		return 0, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var state progIDStateFile
	if err := json.Unmarshal(data, &state); err != nil {
		return 0, err
	}
	if state.Version != progIDStateFileVersion {
		return 0, fmt.Errorf("unsupported version %d", state.Version)
	}
	if state.ReservedThrough < 0 {
		return 0, fmt.Errorf("negative reserved ID %d", state.ReservedThrough)
	}
	return state.ReservedThrough, nil
}

func saveProgIDState(path string, reservedThrough int64) error {
	if path == "" {
		return nil
	}
	state := progIDStateFile{
		Version:         progIDStateFileVersion,
		ReservedThrough: reservedThrough,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return osutil.WriteFileAtomically(path, data)
}

func maxPersistedProgID(workdir string) int64 {
	if workdir == "" {
		return 0
	}
	maxID, err := loadProgIDState(progIDStatePath(workdir))
	if err != nil {
		log.Logf(0, "failed to load runtime program ID state: %v", err)
	}
	maxID = maxInt64(maxID, maxProgIDFromMismatchStore(workdir))
	maxID = maxInt64(maxID, maxProgIDFromStraceLogs(workdir))
	return maxID
}

func maxProgIDFromMismatchStore(workdir string) int64 {
	dir := filepath.Join(workdir, "runtime-mismatches")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		log.Logf(0, "failed to scan runtime mismatch reports: %v", err)
		return 0
	}
	var maxID int64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if parentID, reproID, ok := parseMismatchDirProgIDs(entry.Name()); ok {
			maxID = maxInt64(maxID, parentID)
			maxID = maxInt64(maxID, reproID)
			continue
		}
		maxID = maxInt64(maxID, maxProgIDFromMismatchReport(filepath.Join(dir, entry.Name(), "report.json")))
	}
	return maxID
}

func maxProgIDFromMismatchReport(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var report struct {
		ParentProgID int64 `json:"parent_prog_id"`
		ReproProgID  int64 `json:"repro_prog_id"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return 0
	}
	return maxInt64(report.ParentProgID, report.ReproProgID)
}

func maxProgIDFromStraceLogs(workdir string) int64 {
	maxID := maxProgIDFromStraceDir(filepath.Join(workdir, "strace-log"))
	runtimesDir := filepath.Join(workdir, "runtimes")
	entries, err := os.ReadDir(runtimesDir)
	if errors.Is(err, os.ErrNotExist) {
		return maxID
	}
	if err != nil {
		log.Logf(0, "failed to scan runtime strace directories: %v", err)
		return maxID
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(runtimesDir, entry.Name(), "strace-log")
		maxID = maxInt64(maxID, maxProgIDFromStraceDir(dir))
	}
	return maxID
}

func maxProgIDFromStraceDir(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		log.Logf(0, "failed to scan strace logs in %s: %v", dir, err)
		return 0
	}
	var maxID int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if id, ok := parseStraceLogProgID(entry.Name()); ok {
			maxID = maxInt64(maxID, id)
		}
	}
	return maxID
}

func parseMismatchDirProgIDs(name string) (int64, int64, bool) {
	if !strings.HasPrefix(name, "prog") {
		return 0, 0, false
	}
	rest := strings.TrimPrefix(name, "prog")
	parent, repro, ok := strings.Cut(rest, "-repro")
	if !ok {
		return 0, 0, false
	}
	parentID, ok := parsePositiveInt64(parent)
	if !ok {
		return 0, 0, false
	}
	reproID, ok := parsePositiveInt64(repro)
	if !ok {
		return 0, 0, false
	}
	return parentID, reproID, true
}

func parseStraceLogProgID(name string) (int64, bool) {
	const prefix = "strace.prog"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".log") {
		return 0, false
	}
	rest := strings.TrimPrefix(name, prefix)
	id, _, ok := strings.Cut(rest, ".")
	if !ok {
		return 0, false
	}
	return parsePositiveInt64(id)
}

func parsePositiveInt64(value string) (int64, bool) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
