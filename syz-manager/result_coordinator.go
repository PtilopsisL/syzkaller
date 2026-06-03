// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
)

type runtimeResult struct {
	Runtime    string              `json:"runtime"`
	Status     queue.Status        `json:"status"`
	StatusName string              `json:"status_name"`
	Err        string              `json:"err,omitempty"`
	Calls      []runtimeCallResult `json:"calls,omitempty"`
}

type runtimeCallResult struct {
	Index   int              `json:"index"`
	Name    string           `json:"name,omitempty"`
	Flags   flatrpc.CallFlag `json:"flags"`
	Error   int32            `json:"error"`
	Sctrace string           `json:"sctrace,omitempty"`
}

type normalizedRuntimeResult struct {
	Status queue.Status        `json:"status"`
	Err    string              `json:"err,omitempty"`
	Calls  []runtimeCallResult `json:"calls,omitempty"`
}

type runtimeMismatch struct {
	Reason     string                              `json:"reason"`
	Runtimes   []string                            `json:"runtimes"`
	Normalized map[string]*normalizedRuntimeResult `json:"normalized"`
}

func summarizeRuntimeResult(runtimeName string, req *queue.Request, res *queue.Result) *runtimeResult {
	ret := &runtimeResult{
		Runtime:    runtimeName,
		Status:     res.Status,
		StatusName: res.Status.String(),
	}
	if res.Err != nil {
		ret.Err = res.Err.Error()
	}
	if res.Info == nil {
		return ret
	}
	for i, call := range res.Info.Calls {
		callResult := runtimeCallResult{Index: i}
		if req.Prog != nil && i < len(req.Prog.Calls) {
			callResult.Name = req.Prog.CallName(i)
		}
		if call != nil {
			callResult.Flags = call.Flags
			callResult.Error = call.Error
			callResult.Sctrace = string(call.Sctrace)
		}
		ret.Calls = append(ret.Calls, callResult)
	}
	return ret
}

func (coord *multiRuntimeCoordinator) handleCompletedRun(run *programRun) {
	mismatch := compareRuntimeResults(run.Results)
	if mismatch == nil {
		return
	}
	switch run.Stage {
	case runStageFuzz:
		log.Logf(1, "program %d has cross-runtime result mismatch; scheduling repro", run.ID)
		coord.enqueueMismatchRepro(run)
	case runStageRepro:
		if coord.store == nil {
			log.Logf(1, "confirmed runtime mismatch for program %d; no mismatch store configured",
				run.ParentID)
			return
		}
		path, err := coord.store.Save(run, mismatch)
		if err != nil {
			log.Logf(0, "failed to save runtime mismatch for program %d: %v", run.ParentID, err)
			return
		}
		log.Logf(0, "confirmed runtime mismatch for program %d; saved report to %s",
			run.ParentID, path)
	default:
		panic(fmt.Sprintf("unknown multi-runtime run stage %d", run.Stage))
	}
}

func compareRuntimeResults(results map[string]*runtimeResult) *runtimeMismatch {
	if len(results) < 2 {
		return nil
	}
	names := sortedRuntimeNames(results)
	normalized := make(map[string]*normalizedRuntimeResult, len(results))
	for _, name := range names {
		result := results[name]
		if result.Status == queue.Unsupported {
			return nil
		}
		normalized[name] = normalizeRuntimeResult(result)
	}
	reference := normalized[names[0]]
	for _, name := range names[1:] {
		if !reflect.DeepEqual(reference, normalized[name]) {
			return &runtimeMismatch{
				Reason:     "runtime results differ after normalization",
				Runtimes:   names,
				Normalized: normalized,
			}
		}
	}
	return nil
}

func normalizeRuntimeResult(result *runtimeResult) *normalizedRuntimeResult {
	// Intentionally a no-op placeholder for now. Future noise filters should be added here.
	return &normalizedRuntimeResult{
		Status: result.Status,
		Err:    result.Err,
		Calls:  append([]runtimeCallResult(nil), result.Calls...),
	}
}

func (coord *multiRuntimeCoordinator) enqueueMismatchRepro(initial *programRun) {
	reproID := coord.nextID.Add(1)
	expected := copyExpectedRuntimes(initial.Expected)
	reproRun := &programRun{
		ID:             reproID,
		ParentID:       initial.ID,
		Stage:          runStageRepro,
		Prog:           initial.Prog.Clone(),
		ProgData:       append([]byte(nil), initial.ProgData...),
		Important:      true,
		Expected:       expected,
		Results:        map[string]*runtimeResult{},
		InitialResults: copyRuntimeResults(initial.Results),
	}

	coord.mu.Lock()
	coord.runs[reproID] = reproRun
	queues := make(map[string]*queue.PlainQueue, len(expected))
	for runtimeName := range expected {
		queues[runtimeName] = coord.runtimeQueueLocked(runtimeName)
	}
	coord.mu.Unlock()

	for runtimeName, runtimeQueue := range queues {
		req := &queue.Request{
			ProgID:    reproID,
			Prog:      reproRun.Prog.Clone(),
			Important: true,
		}
		fuzzer.EnableSyscallTrace(req)
		req.OnDone(func(r *queue.Request, res *queue.Result) bool {
			coord.recordResult(runtimeName, r, res)
			return true
		})
		runtimeQueue.Submit(req)
	}
}

func sortedRuntimeNames(results map[string]*runtimeResult) []string {
	ret := make([]string, 0, len(results))
	for name := range results {
		ret = append(ret, name)
	}
	sort.Strings(ret)
	return ret
}

func copyExpectedRuntimes(expected map[string]bool) map[string]bool {
	ret := make(map[string]bool, len(expected))
	for name, enabled := range expected {
		ret[name] = enabled
	}
	return ret
}

func copyRuntimeResults(results map[string]*runtimeResult) map[string]*runtimeResult {
	ret := make(map[string]*runtimeResult, len(results))
	for name, result := range results {
		copyResult := *result
		copyResult.Calls = append([]runtimeCallResult(nil), result.Calls...)
		ret[name] = &copyResult
	}
	return ret
}

type mismatchStore struct {
	baseDir string
}

func newMismatchStore(workdir string) *mismatchStore {
	if workdir == "" {
		return nil
	}
	return &mismatchStore{
		baseDir: filepath.Join(workdir, "runtime-mismatches"),
	}
}

type storedMismatchReport struct {
	ParentProgID   int64                               `json:"parent_prog_id"`
	ReproProgID    int64                               `json:"repro_prog_id"`
	Reason         string                              `json:"reason"`
	Runtimes       []string                            `json:"runtimes"`
	InitialResults map[string]*runtimeResult           `json:"initial_results"`
	ReproResults   map[string]*runtimeResult           `json:"repro_results"`
	Normalized     map[string]*normalizedRuntimeResult `json:"normalized"`
}

func (store *mismatchStore) Save(run *programRun, mismatch *runtimeMismatch) (string, error) {
	if store == nil {
		return "", nil
	}
	dir := filepath.Join(store.baseDir, fmt.Sprintf("prog%d-repro%d", run.ParentID, run.ID))
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "repro.prog"), run.ProgData, 0o644); err != nil {
		return "", err
	}
	report := &storedMismatchReport{
		ParentProgID:   run.ParentID,
		ReproProgID:    run.ID,
		Reason:         mismatch.Reason,
		Runtimes:       mismatch.Runtimes,
		InitialResults: run.InitialResults,
		ReproResults:   run.Results,
		Normalized:     mismatch.Normalized,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), data, 0o644); err != nil {
		return "", err
	}
	for runtimeName, result := range run.Results {
		var text strings.Builder
		for _, call := range result.Calls {
			if call.Sctrace == "" {
				continue
			}
			text.WriteString(call.Sctrace)
			if !strings.HasSuffix(call.Sctrace, "\n") {
				text.WriteByte('\n')
			}
		}
		if text.Len() == 0 {
			continue
		}
		name := sanitizeFileName(runtimeName) + ".strace.log"
		if err := os.WriteFile(filepath.Join(dir, "logs", name), []byte(text.String()), 0o644); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func sanitizeFileName(name string) string {
	return strings.Map(func(ch rune) rune {
		switch {
		case ch >= 'a' && ch <= 'z':
			return ch
		case ch >= 'A' && ch <= 'Z':
			return ch
		case ch >= '0' && ch <= '9':
			return ch
		case ch == '.' || ch == '-' || ch == '_':
			return ch
		default:
			return '_'
		}
	}, name)
}
