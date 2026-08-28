// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
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
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type runtimeResult struct {
	Runtime          string              `json:"runtime"`
	RuntimeVersion   string              `json:"runtime_version,omitempty"`
	OutputPolicyHash string              `json:"output_policy_hash,omitempty"`
	Status           queue.Status        `json:"status"`
	StatusName       string              `json:"status_name"`
	Err              string              `json:"err,omitempty"`
	Calls            []runtimeCallResult `json:"calls,omitempty"`
}

type runtimeCallResult struct {
	Index            int                     `json:"index"`
	Name             string                  `json:"name,omitempty"`
	Args             []*runtimeCallArg       `json:"args,omitempty"`
	Flags            flatrpc.CallFlag        `json:"flags"`
	Error            int32                   `json:"error"`
	ReturnValue      *int64                  `json:"return_value,omitempty"`
	ReturnType       string                  `json:"return_type,omitempty"`
	ReturnIsResource bool                    `json:"return_is_resource,omitempty"`
	Outputs          []*runtimeOutputCapture `json:"outputs,omitempty"`
	Sctrace          string                  `json:"sctrace,omitempty"`
}

type runtimeCallArg struct {
	Name        string              `json:"name,omitempty"`
	Type        string              `json:"type,omitempty"`
	Dir         string              `json:"dir,omitempty"`
	Kind        string              `json:"kind"`
	Value       *uint64             `json:"value,omitempty"`
	ValueNames  []string            `json:"value_names,omitempty"`
	Size        uint64              `json:"size,omitempty"`
	Address     *uint64             `json:"address,omitempty"`
	Args        []*runtimeCallArg   `json:"args,omitempty"`
	Selected    string              `json:"selected,omitempty"`
	DataSummary *runtimeDataSummary `json:"data_summary,omitempty"`
	Ref         string              `json:"ref,omitempty"`
	OpDiv       *uint64             `json:"op_div,omitempty"`
	OpAdd       *uint64             `json:"op_add,omitempty"`
}

type runtimeDataSummary struct {
	Size         uint64 `json:"size"`
	CapturedSize uint64 `json:"captured_size,omitempty"`
	Hash         string `json:"hash,omitempty"`
	PreviewHex   string `json:"preview_hex,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
	Output       bool   `json:"output,omitempty"`
}

type runtimeOutputCapture struct {
	ID           uint32                  `json:"id"`
	Path         string                  `json:"path,omitempty"`
	Type         string                  `json:"type,omitempty"`
	Size         uint64                  `json:"size,omitempty"`
	CapturedSize uint64                  `json:"captured_size,omitempty"`
	Missing      bool                    `json:"missing,omitempty"`
	Faulted      bool                    `json:"faulted,omitempty"`
	Truncated    bool                    `json:"truncated,omitempty"`
	Values       []*runtimeDecodedOutput `json:"values,omitempty"`
}

type runtimeCanonicalOutput struct {
	Kind      string  `json:"kind"`
	Domain    string  `json:"domain,omitempty"`
	Class     string  `json:"class,omitempty"`
	State     string  `json:"state,omitempty"`
	Region    string  `json:"region,omitempty"`
	Offset    *uint64 `json:"offset,omitempty"`
	Exact     *uint64 `json:"exact,omitempty"`
	Alignment uint64  `json:"alignment,omitempty"`
}

type runtimeDecodedOutput struct {
	Path             string                  `json:"path"`
	Type             string                  `json:"type"`
	Dir              string                  `json:"dir"`
	Kind             string                  `json:"kind"`
	Size             uint64                  `json:"size,omitempty"`
	Value            *uint64                 `json:"value,omitempty"`
	ValueNames       []string                `json:"value_names,omitempty"`
	RawHex           string                  `json:"raw_hex,omitempty"`
	Truncated        bool                    `json:"truncated,omitempty"`
	DataSummary      *runtimeDataSummary     `json:"data_summary,omitempty"`
	OutputPolicy     prog.OutputPolicy       `json:"output_policy"`
	PolicySource     string                  `json:"policy_source,omitempty"`
	IdentitySpecial  bool                    `json:"identity_special,omitempty"`
	CanonicalValue   *runtimeCanonicalOutput `json:"canonical_value,omitempty"`
	NormalizationErr string                  `json:"normalization_error,omitempty"`
}

type runtimeCallExecutionState string

const (
	callNotExecuted   runtimeCallExecutionState = "not_executed"
	callStarted       runtimeCallExecutionState = "started_but_unfinished"
	callFinishedError runtimeCallExecutionState = "finished_error"
	callFinishedOK    runtimeCallExecutionState = "finished_ok"
)

type comparisonRuntimeCallResult struct {
	Index          int                       `json:"index"`
	Name           string                    `json:"name,omitempty"`
	State          runtimeCallExecutionState `json:"state"`
	Error          *int32                    `json:"error,omitempty"`
	ReturnValue    *int64                    `json:"return_value,omitempty"`
	ReturnResource string                    `json:"return_resource,omitempty"`
	Outputs        []*runtimeOutputCapture   `json:"outputs,omitempty"`
}

type comparisonRuntimeResult struct {
	Status queue.Status                  `json:"status"`
	Err    string                        `json:"err,omitempty"`
	Calls  []comparisonRuntimeCallResult `json:"calls,omitempty"`
}

type comparisonOutcome string

const (
	comparisonOutcomeMismatch     comparisonOutcome = "mismatch"
	comparisonOutcomeInconclusive comparisonOutcome = "inconclusive"
)

type runtimeFieldDifference struct {
	Kind          string         `json:"kind"`
	Path          string         `json:"path"`
	Values        map[string]any `json:"values"`
	CallIndex     *int           `json:"call_index,omitempty"`
	CallName      string         `json:"call_name,omitempty"`
	OutputPolicy  string         `json:"output_policy,omitempty"`
	Signature     string         `json:"signature,omitempty"`
	Fingerprint   string         `json:"fingerprint,omitempty"`
	TriageLabel   string         `json:"triage_label,omitempty"`
	TriageLabelID string         `json:"triage_label_id,omitempty"`
	TriageNote    string         `json:"triage_note,omitempty"`
}

type runtimeMismatch struct {
	Outcome           comparisonOutcome                   `json:"outcome"`
	Reason            string                              `json:"reason"`
	Runtimes          []string                            `json:"runtimes"`
	Compared          map[string]*comparisonRuntimeResult `json:"compared"`
	StableDifferences []runtimeFieldDifference            `json:"stable_differences"`
	Triage            runtimeDiffTriage                   `json:"triage,omitempty"`
	UnstableFields    map[string][]string                 `json:"unstable_fields,omitempty"`
	InvalidSamples    map[string][]string                 `json:"invalid_samples,omitempty"`
	PartialSamples    map[string][]string                 `json:"partial_samples,omitempty"`
}

func summarizeRuntimeResult(runtimeName string, req *queue.Request, res *queue.Result,
	policies ...*runtimeOutputPolicyStore) *runtimeResult {
	var outputPolicies *runtimeOutputPolicyStore
	if len(policies) != 0 {
		outputPolicies = policies[0]
	}
	ret := &runtimeResult{
		Runtime: runtimeName, Status: res.Status, StatusName: res.Status.String(),
	}
	if outputPolicies != nil {
		ret.OutputPolicyHash = outputPolicies.hash
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
			callResult.Args = summarizeCallArgs(req.Prog, i)
			if retType := req.Prog.Calls[i].Meta.Ret; retType != nil {
				callResult.ReturnType = retType.String()
				_, callResult.ReturnIsResource = retType.(*prog.ResourceType)
			}
		}
		if call != nil {
			callResult.Flags = call.Flags
			callResult.Error = call.Error
			if call.ReturnValueValid {
				callResult.ReturnValue = int64Ptr(call.ReturnValue)
			}
			if req.Prog != nil && req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectOutputs != 0 {
				callResult.Outputs = summarizeCallOutputs(req.Prog, i, call.Outputs)
				applyRuntimeOutputPolicies(callResult.Name, callResult.Outputs, outputPolicies)
			}
			callResult.Sctrace = string(call.Sctrace)
		}
		ret.Calls = append(ret.Calls, callResult)
	}
	normalizeRuntimeOutputs(req.Prog, ret)
	return ret
}

func (coord *multiRuntimeCoordinator) handleCompletedRun(run *programRun) {
	switch run.Stage {
	case runStageFuzz:
		mismatch := compareRuntimeResults(coord.comparisonResults(run.Results), coord.diffLabels)
		if mismatch == nil {
			return
		}
		if mismatch.Outcome == comparisonOutcomeInconclusive {
			log.Logf(1, "program %d has an incomplete cross-runtime result; scheduling validation repro", run.ID)
		} else {
			log.Logf(1, "program %d has cross-runtime result mismatch; scheduling repro", run.ID)
		}
		coord.enqueueMismatchRepro(run)
	case runStageRepro:
		coord.handleCompletedRepro(run)
	case runStageMinimize:
		mismatch := compareRuntimeSamples(coord.comparisonSamples(run.Samples), coord.diffLabels)
		if run.Completion == nil {
			panic(fmt.Sprintf("minimize run %d has no completion channel", run.ID))
		}
		select {
		case run.Completion <- runtimeComparisonCompletion{Mismatch: mismatch}:
		case <-coord.done:
		}
	default:
		panic(fmt.Sprintf("unknown multi-runtime run stage %d", run.Stage))
	}
}

func (coord *multiRuntimeCoordinator) handleCompletedRepro(run *programRun) {
	mismatch := compareRuntimeSamples(coord.comparisonSamples(run.Samples), coord.diffLabels)
	if mismatch == nil {
		return
	}
	if mismatch.Outcome == comparisonOutcomeMismatch && coord.store != nil {
		identity, callIndex, ok := firstRuntimeMismatchCallIdentity(run.Prog, mismatch)
		if ok {
			// Preserve the stable pre-minimization reproducer and its samples for
			// comparison with the separately saved final minimized report.
			coord.saveRuntimeReport(run, mismatch)
			log.Logf(1, "runtime mismatch for program %d reproduced; minimizing first mismatching syscall %s",
				run.ParentID, identity.CallName)
			go coord.minimizeRuntimeMismatch(run, mismatch, identity, callIndex)
			return
		}
		log.Logf(1, "runtime mismatch for program %d has no syscall-scoped difference; saving without minimization",
			run.ParentID)
	}
	coord.saveRuntimeReport(run, mismatch)
}

func (coord *multiRuntimeCoordinator) saveRuntimeReport(run *programRun, mismatch *runtimeMismatch) {
	store := coord.store
	resultKind := "runtime mismatch"
	if mismatch.Outcome == comparisonOutcomeInconclusive {
		if len(mismatch.UnstableFields) == 0 {
			log.Logf(1, "runtime comparison for program %d is inconclusive; report not saved",
				run.ParentID)
			return
		}
		store = coord.unstableStore
		resultKind = "unstable runtime result"
	} else if mismatch.Outcome != comparisonOutcomeMismatch {
		log.Logf(1, "runtime comparison for program %d is inconclusive; report not saved",
			run.ParentID)
		return
	}
	if store == nil {
		log.Logf(1, "%s for program %d; no report store configured", resultKind, run.ParentID)
		return
	}
	reportRun := *run
	reportRun.InitialResults = coord.comparisonResults(run.InitialResults)
	reportRun.Samples = coord.comparisonSamples(run.Samples)
	path, err := store.Save(&reportRun, mismatch)
	if err != nil {
		log.Logf(0, "failed to save %s for program %d: %v", resultKind, run.ParentID, err)
		return
	}
	log.Logf(0, "%s for program %d; saved report to %s", resultKind, run.ParentID, path)
}

func (coord *multiRuntimeCoordinator) comparisonResults(
	results map[string]*runtimeResult) map[string]*runtimeResult {
	names := coord.comparisonRuntimeNames()
	ret := make(map[string]*runtimeResult, len(results))
	for slotName, result := range results {
		runtimeName := comparisonRuntimeName(slotName, names)
		if _, ok := ret[runtimeName]; ok {
			panic(fmt.Sprintf("runtime comparison name %q is not unique", runtimeName))
		}
		ret[runtimeName] = comparisonRuntimeResultWithName(result, runtimeName)
	}
	return ret
}

func (coord *multiRuntimeCoordinator) comparisonRuntimeNames() map[string]string {
	coord.mu.Lock()
	defer coord.mu.Unlock()
	names := make(map[string]string, len(coord.comparisonNames))
	for slotName, runtimeName := range coord.comparisonNames {
		names[slotName] = runtimeName
	}
	return names
}

func (coord *multiRuntimeCoordinator) comparisonSamples(
	samples map[string][]*runtimeResult) map[string][]*runtimeResult {
	names := coord.comparisonRuntimeNames()
	ret := make(map[string][]*runtimeResult, len(samples))
	for slotName, runtimeSamples := range samples {
		runtimeName := comparisonRuntimeName(slotName, names)
		if _, ok := ret[runtimeName]; ok {
			panic(fmt.Sprintf("runtime comparison name %q is not unique", runtimeName))
		}
		ret[runtimeName] = make([]*runtimeResult, len(runtimeSamples))
		for index, result := range runtimeSamples {
			ret[runtimeName][index] = comparisonRuntimeResultWithName(result, runtimeName)
		}
	}
	return ret
}

func comparisonRuntimeName(slotName string, names map[string]string) string {
	if runtimeName := names[slotName]; runtimeName != "" {
		return runtimeName
	}
	return slotName
}

func comparisonRuntimeResultWithName(result *runtimeResult, runtimeName string) *runtimeResult {
	if result == nil {
		return nil
	}
	copyResult := *result
	copyResult.Runtime = runtimeName
	return &copyResult
}

func compareRuntimeResults(results map[string]*runtimeResult, labels ...*runtimeDiffLabelStore) *runtimeMismatch {
	if len(results) < 2 {
		return nil
	}
	// Keep the historical behavior: a runtime that does not support a
	// program is not evidence of an ABI mismatch.
	for _, result := range results {
		if result != nil && result.Status == queue.Unsupported {
			return nil
		}
	}
	samples := make(map[string][]*runtimeResult, len(results))
	for name, result := range results {
		samples[name] = []*runtimeResult{result}
	}
	return compareRuntimeSamples(samples, labels...)
}

func comparisonRuntimeResultFor(result *runtimeResult) *comparisonRuntimeResult {
	return comparisonRuntimeResultForPrefix(result, -1)
}

func comparisonRuntimeResultForPrefix(result *runtimeResult, maxCalls int) *comparisonRuntimeResult {
	ret := &comparisonRuntimeResult{
		Status: result.Status,
		Err:    result.Err,
	}
	calls := result.Calls
	if maxCalls >= 0 && len(calls) > maxCalls {
		calls = calls[:maxCalls]
	}
	for _, call := range calls {
		state := runtimeCallExecutionStateFor(call)
		comparedCall := comparisonRuntimeCallResult{
			Index: call.Index,
			Name:  call.Name,
			State: state,
		}
		switch state {
		case callFinishedError:
			comparedCall.Error = int32Ptr(call.Error)
		case callFinishedOK:
			if call.ReturnIsResource {
				comparedCall.ReturnResource = call.ReturnType
			} else {
				comparedCall.ReturnValue = cloneInt64(call.ReturnValue)
			}
			comparedCall.Outputs = comparisonRuntimeOutputCaptures(call.Outputs)
		}
		ret.Calls = append(ret.Calls, comparedCall)
	}
	return ret
}

const (
	// These values are protocol sentinels rather than kernel errno values. 998 is
	// emitted by the executor for a call for which no result record was produced;
	// 999 is emitted by the RPC runner when the executor returned too few records.
	executorMissingCallError = int32(998)
	runnerMissingCallError   = int32(999)
)

type runtimeResultCompletion struct {
	prefix      int
	partial     bool
	description string
}

// runtimeResultCompletionFor returns the prefix of calls with a terminal
// execution state. A successful result with a non-terminal call is an
// incomplete executor result, not evidence that the call returned a different
// ABI value. Non-success statuses are kept as explicit crash/timeout results;
// their status remains comparable by the normal status checks.
func runtimeResultCompletionFor(result *runtimeResult) runtimeResultCompletion {
	if result == nil {
		return runtimeResultCompletion{}
	}
	if result.Status != queue.Success {
		return runtimeResultCompletion{prefix: len(result.Calls)}
	}
	for index, call := range result.Calls {
		state := runtimeCallExecutionStateFor(call)
		if state == callFinishedOK || state == callFinishedError {
			continue
		}
		description := fmt.Sprintf("call %d (%s): %s", call.Index, call.Name, state)
		switch call.Error {
		case executorMissingCallError:
			description += fmt.Sprintf(" (executor did not emit a call result; sentinel error %d)", call.Error)
		case runnerMissingCallError:
			description += fmt.Sprintf(" (runner did not receive a call result; sentinel error %d)", call.Error)
		}
		return runtimeResultCompletion{
			prefix:      index,
			partial:     true,
			description: description,
		}
	}
	return runtimeResultCompletion{prefix: len(result.Calls)}
}

func runtimeCallExecutionStateFor(call runtimeCallResult) runtimeCallExecutionState {
	if call.Flags&flatrpc.CallFlagExecuted == 0 {
		return callNotExecuted
	}
	if call.Flags&flatrpc.CallFlagFinished == 0 {
		return callStarted
	}
	if call.Error != 0 {
		return callFinishedError
	}
	return callFinishedOK
}

func runtimeResultComparisonIssue(result *runtimeResult) string {
	if result == nil {
		return "missing runtime result"
	}
	const knownFlags = flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished |
		flatrpc.CallFlagBlocked | flatrpc.CallFlagFaultInjected |
		flatrpc.CallFlagCoverageOverflow
	for _, call := range result.Calls {
		if unknown := call.Flags &^ knownFlags; unknown != 0 {
			return fmt.Sprintf("call %d (%s) has unknown flags %#x", call.Index, call.Name, unknown)
		}
		if call.Flags&flatrpc.CallFlagFinished != 0 &&
			call.Flags&flatrpc.CallFlagExecuted == 0 {
			return fmt.Sprintf("call %d (%s) finished without being executed", call.Index, call.Name)
		}
		if call.Flags&flatrpc.CallFlagFaultInjected != 0 {
			return fmt.Sprintf("call %d (%s) used fault injection", call.Index, call.Name)
		}
		if result.Status != queue.Success {
			continue
		}
		if runtimeCallExecutionStateFor(call) != callFinishedOK {
			continue
		}
		if call.ReturnValue == nil {
			return fmt.Sprintf("call %d (%s) has no return value", call.Index, call.Name)
		}
		for _, capture := range call.Outputs {
			if capture != nil && (capture.Missing || capture.Faulted) {
				return fmt.Sprintf("call %d (%s) has an invalid output capture", call.Index, call.Name)
			}
		}
	}
	return ""
}

func comparisonRuntimeOutputCaptures(captures []*runtimeOutputCapture) []*runtimeOutputCapture {
	ret := cloneRuntimeOutputCaptures(captures)
	for _, capture := range ret {
		if capture == nil {
			continue
		}
		values := capture.Values[:0]
		for _, output := range capture.Values {
			if output == nil {
				values = append(values, output)
				continue
			}
			kind := output.OutputPolicy.EffectiveKind()
			if kind == prog.OutputPolicyReserved ||
				(kind == prog.OutputPolicyTimestamp && output.OutputPolicy.Mode != "exact") {
				continue
			}
			if output.CanonicalValue != nil && output.NormalizationErr == "" {
				clearRuntimeOutputRawValue(output)
			} else if output.OutputPolicy.Kind == "" && output.Kind == "result" {
				// Backward compatibility for reports/tests produced before output
				// policies were attached. New results always carry an explicit policy.
				clearRuntimeOutputRawValue(output)
			}
			values = append(values, output)
		}
		capture.Values = values
	}
	return ret
}

func clearRuntimeOutputRawValue(output *runtimeDecodedOutput) {
	output.Value = nil
	output.ValueNames = nil
	output.RawHex = ""
	output.DataSummary = nil
	output.IdentitySpecial = false
}

type observedComparisonValue struct {
	Present bool
	Value   any
}

type runtimeSampleComparison struct {
	names        []string
	views        map[string][]*comparisonRuntimeResult
	rawSamples   map[string][]*runtimeResult
	labels       *runtimeDiffLabelStore
	result       *runtimeMismatch
	partial      bool
	commonPrefix int
}

func compareRuntimeSamples(samples map[string][]*runtimeResult, labels ...*runtimeDiffLabelStore) *runtimeMismatch {
	if len(samples) < 2 {
		return nil
	}
	names := sortedRuntimeSampleNames(samples)
	var diffLabels *runtimeDiffLabelStore
	if len(labels) != 0 {
		diffLabels = labels[0]
	}
	comparison := &runtimeSampleComparison{
		names:      names,
		rawSamples: samples,
		labels:     diffLabels,
		views:      make(map[string][]*comparisonRuntimeResult, len(samples)),
		result: &runtimeMismatch{
			Runtimes:          names,
			Compared:          make(map[string]*comparisonRuntimeResult, len(samples)),
			StableDifferences: []runtimeFieldDifference{},
			UnstableFields:    make(map[string][]string),
			InvalidSamples:    make(map[string][]string),
			PartialSamples:    make(map[string][]string),
		},
	}
	validSamples := make(map[string][]*runtimeResult, len(samples))
	commonPrefix := -1
	for _, name := range names {
		runtimeSamples := samples[name]
		if len(runtimeSamples) == 0 {
			comparison.result.InvalidSamples[name] = []string{"no repro samples"}
			continue
		}
		for index, sample := range runtimeSamples {
			if issue := runtimeResultComparisonIssue(sample); issue != "" {
				comparison.result.InvalidSamples[name] = append(
					comparison.result.InvalidSamples[name],
					fmt.Sprintf("sample %d: %s", index+1, issue))
				continue
			}
			validSamples[name] = append(validSamples[name], sample)
			prefix := len(sample.Calls)
			if sample.Status == queue.Success {
				completion := runtimeResultCompletionFor(sample)
				prefix = completion.prefix
				if completion.partial {
					comparison.partial = true
					comparison.result.PartialSamples[name] = append(
						comparison.result.PartialSamples[name],
						fmt.Sprintf("sample %d: %s", index+1, completion.description))
				}
			}
			if commonPrefix == -1 || prefix < commonPrefix {
				commonPrefix = prefix
			}
		}
	}
	if len(comparison.result.InvalidSamples) != 0 {
		return comparison.finish()
	}
	if commonPrefix == -1 {
		commonPrefix = 0
	}
	comparison.commonPrefix = commonPrefix
	for _, name := range names {
		for _, sample := range validSamples[name] {
			view := comparisonRuntimeResultFor(sample)
			if comparison.partial {
				view = comparisonRuntimeResultForPrefix(sample, commonPrefix)
			}
			comparison.views[name] = append(comparison.views[name], view)
			if comparison.result.Compared[name] == nil {
				comparison.result.Compared[name] = view
			}
		}
	}

	statusValues, stable, different := comparison.field("status", "status", -1, "",
		func(result *comparisonRuntimeResult) observedComparisonValue {
			return observedComparisonValue{Present: true, Value: result.Status}
		})
	if !stable {
		return comparison.finish()
	}
	if different && comparison.partial {
		if count := len(comparison.result.StableDifferences); count != 0 &&
			comparison.result.StableDifferences[count-1].Kind == "status" {
			comparison.result.StableDifferences = comparison.result.StableDifferences[:count-1]
		}
		for _, name := range names {
			comparison.result.UnstableFields[name] = append(comparison.result.UnstableFields[name], "status")
		}
		different = false
	}
	if different {
		return comparison.finish()
	}
	status := statusValues[names[0]].Value.(queue.Status)
	if status == queue.Unsupported {
		return nil
	}
	_, requestStable, requestDifferent := comparison.field("request_error", "err", -1, "",
		func(result *comparisonRuntimeResult) observedComparisonValue {
			return observedComparisonValue{Present: true, Value: result.Err}
		})
	if requestStable && requestDifferent && comparison.partial {
		if count := len(comparison.result.StableDifferences); count != 0 &&
			comparison.result.StableDifferences[count-1].Kind == "request_error" {
			comparison.result.StableDifferences = comparison.result.StableDifferences[:count-1]
		}
		for _, name := range names {
			comparison.result.UnstableFields[name] = append(comparison.result.UnstableFields[name], "err")
		}
	}
	if status != queue.Success {
		return comparison.finish()
	}

	if !comparison.partial {
		_, callCountStable, callCountDifferent := comparison.field("call_count", "calls", -1, "",
			func(result *comparisonRuntimeResult) observedComparisonValue {
				return observedComparisonValue{Present: true, Value: len(result.Calls)}
			})
		if callCountStable && callCountDifferent {
			return comparison.finish()
		}
	}
	maxCalls := comparison.maxCallCount()
	if comparison.partial {
		maxCalls = comparison.commonPrefix
	}
	for callIndex := 0; callIndex < maxCalls; callIndex++ {
		index := callIndex
		presenceValues, presenceStable, presenceDifferent := comparison.field(
			"call_presence", fmt.Sprintf("calls[%d]", index), index, "",
			func(result *comparisonRuntimeResult) observedComparisonValue {
				return observedComparisonValue{Present: true, Value: index < len(result.Calls)}
			})
		if !presenceStable || presenceDifferent || !presenceValues[names[0]].Value.(bool) {
			continue
		}
		callName := comparison.views[names[0]][0].Calls[index].Name
		_, nameStable, nameDifferent := comparison.field(
			"call_name", fmt.Sprintf("calls[%d].name", index), index, callName,
			func(result *comparisonRuntimeResult) observedComparisonValue {
				return observedComparisonValue{Present: true, Value: result.Calls[index].Name}
			})
		if !nameStable || nameDifferent {
			continue
		}
		stateValues, stateStable, stateDifferent := comparison.field(
			"call_state", fmt.Sprintf("calls[%d].state", index), index, callName,
			func(result *comparisonRuntimeResult) observedComparisonValue {
				return observedComparisonValue{Present: true, Value: result.Calls[index].State}
			})
		if !stateStable || stateDifferent {
			continue
		}
		state := stateValues[names[0]].Value.(runtimeCallExecutionState)
		switch state {
		case callFinishedError:
			comparison.field("errno", fmt.Sprintf("calls[%d].error", index), index, callName,
				func(result *comparisonRuntimeResult) observedComparisonValue {
					value := result.Calls[index].Error
					if value == nil {
						return observedComparisonValue{}
					}
					return observedComparisonValue{Present: true, Value: *value}
				})
		case callFinishedOK:
			comparison.field("return_value", fmt.Sprintf("calls[%d].return_value", index),
				index, callName, func(result *comparisonRuntimeResult) observedComparisonValue {
					call := &result.Calls[index]
					if call.ReturnResource != "" {
						return observedComparisonValue{Present: true, Value: map[string]string{
							"resource": call.ReturnResource,
						}}
					}
					if call.ReturnValue == nil {
						return observedComparisonValue{}
					}
					return observedComparisonValue{Present: true, Value: *call.ReturnValue}
				})
			comparison.compareOutputs(index, callName)
		}
	}
	return comparison.finish()
}

func (comparison *runtimeSampleComparison) field(kind, path string, callIndex int, callName string,
	value func(*comparisonRuntimeResult) observedComparisonValue) (
	map[string]observedComparisonValue, bool, bool) {
	values := make(map[string]observedComparisonValue, len(comparison.names))
	allStable := true
	for _, name := range comparison.names {
		samples := comparison.views[name]
		baseline := value(samples[0])
		stable := true
		for _, sample := range samples[1:] {
			if !observedComparisonValuesEqual(baseline, value(sample)) {
				stable = false
				break
			}
		}
		if !stable {
			comparison.result.UnstableFields[name] = append(
				comparison.result.UnstableFields[name], path)
			allStable = false
			continue
		}
		values[name] = baseline
	}
	if !allStable {
		return values, false, false
	}
	reference := values[comparison.names[0]]
	different := false
	for _, name := range comparison.names[1:] {
		if !observedComparisonValuesEqual(reference, values[name]) {
			different = true
			break
		}
	}
	if different {
		diffValues := make(map[string]any, len(values))
		for _, name := range comparison.names {
			if values[name].Present {
				diffValues[name] = values[name].Value
			} else {
				diffValues[name] = nil
			}
		}
		diff := runtimeFieldDifference{
			Kind: kind, Path: path, Values: diffValues, CallName: callName,
		}
		if callIndex >= 0 {
			diff.CallIndex = intPtr(callIndex)
		}
		if kind == "output" {
			for _, observed := range values {
				output, ok := observed.Value.(runtimeDecodedOutput)
				if !ok {
					continue
				}
				diff.OutputPolicy = string(output.OutputPolicy.EffectiveKind())
				if output.OutputPolicy.EffectiveKind() == prog.OutputPolicyVersionIdentity {
					diff.TriageLabel = string(runtimeDiffExpectedVersion)
					diff.TriageLabelID = "output_policy"
					diff.TriageNote = "classified by version_identity output policy"
				}
				break
			}
		}
		comparison.result.StableDifferences = append(comparison.result.StableDifferences, diff)
	}
	return values, true, different
}

func (comparison *runtimeSampleComparison) compareOutputs(callIndex int, callName string) {
	paths := map[string]bool{}
	fieldsBySample := make(map[*comparisonRuntimeResult]map[string]observedComparisonValue)
	for _, runtimeSamples := range comparison.views {
		for _, sample := range runtimeSamples {
			fields := comparisonOutputFields(sample.Calls[callIndex], callIndex)
			fieldsBySample[sample] = fields
			for path := range fields {
				paths[path] = true
			}
		}
	}
	sortedPaths := make([]string, 0, len(paths))
	for path := range paths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)
	for _, path := range sortedPaths {
		fieldPath := path
		comparison.field("output", fieldPath, callIndex, callName,
			func(result *comparisonRuntimeResult) observedComparisonValue {
				return fieldsBySample[result][fieldPath]
			})
	}
}

func comparisonOutputFields(call comparisonRuntimeCallResult,
	callIndex int) map[string]observedComparisonValue {
	ret := map[string]observedComparisonValue{
		fmt.Sprintf("calls[%d].outputs.length", callIndex): {
			Present: true,
			Value:   len(call.Outputs),
		},
	}
	for captureIndex, capture := range call.Outputs {
		capturePath := fmt.Sprintf("calls[%d].outputs.capture[%d]", callIndex, captureIndex)
		if capture == nil {
			ret[capturePath] = observedComparisonValue{Present: true}
			continue
		}
		ret[capturePath] = observedComparisonValue{Present: true, Value: struct {
			ID           uint32 `json:"id"`
			Path         string `json:"path,omitempty"`
			Type         string `json:"type,omitempty"`
			Size         uint64 `json:"size,omitempty"`
			CapturedSize uint64 `json:"captured_size,omitempty"`
			Truncated    bool   `json:"truncated,omitempty"`
		}{
			ID: capture.ID, Path: capture.Path, Type: capture.Type,
			Size: capture.Size, CapturedSize: capture.CapturedSize,
			Truncated: capture.Truncated,
		}}
		for valueIndex, output := range capture.Values {
			path := fmt.Sprintf("%s.value[%d]", capturePath, valueIndex)
			if output != nil && output.Path != "" {
				path = fmt.Sprintf("calls[%d].outputs.%s", callIndex, output.Path)
			}
			if output == nil {
				ret[path] = observedComparisonValue{Present: true}
			} else {
				ret[path] = observedComparisonValue{Present: true, Value: *output}
			}
		}
	}
	return ret
}

func observedComparisonValuesEqual(left, right observedComparisonValue) bool {
	return left.Present == right.Present && reflect.DeepEqual(left.Value, right.Value)
}

func (comparison *runtimeSampleComparison) maxCallCount() int {
	maxCalls := 0
	for _, runtimeSamples := range comparison.views {
		for _, sample := range runtimeSamples {
			maxCalls = max(maxCalls, len(sample.Calls))
		}
	}
	return maxCalls
}

func (comparison *runtimeSampleComparison) finish() *runtimeMismatch {
	annotateRuntimeDifferences(comparison.result.StableDifferences, comparison.rawSamples, comparison.labels)
	comparison.result.Triage = summarizeRuntimeDiffTriage(comparison.result.StableDifferences)
	for name, fields := range comparison.result.UnstableFields {
		sort.Strings(fields)
		comparison.result.UnstableFields[name] = fields
	}
	if len(comparison.result.StableDifferences) != 0 {
		comparison.result.Outcome = comparisonOutcomeMismatch
		comparison.result.Reason = "runtime results differ in stable fields"
		return comparison.result
	}
	if len(comparison.result.UnstableFields) != 0 || len(comparison.result.InvalidSamples) != 0 || len(comparison.result.PartialSamples) != 0 {
		comparison.result.Outcome = comparisonOutcomeInconclusive
		comparison.result.Reason = "runtime comparison is inconclusive"
		return comparison.result
	}
	return nil
}

func sortedRuntimeSampleNames(samples map[string][]*runtimeResult) []string {
	ret := make([]string, 0, len(samples))
	for name := range samples {
		ret = append(ret, name)
	}
	sort.Strings(ret)
	return ret
}

func summarizeCallArgs(p *prog.Prog, callIndex int) []*runtimeCallArg {
	call := p.Calls[callIndex]
	refs := resultRefs(p)
	ret := make([]*runtimeCallArg, 0, len(call.Args))
	for i, arg := range call.Args {
		name := ""
		if i < len(call.Meta.Args) {
			name = call.Meta.Args[i].Name
		}
		ret = append(ret, summarizeArg(p.Target, refs, name, arg))
	}
	return ret
}

func resultRefs(p *prog.Prog) map[*prog.ResultArg]string {
	refs := make(map[*prog.ResultArg]string)
	for i, call := range p.Calls {
		if call.Ret != nil {
			refs[call.Ret] = fmt.Sprintf("call%d.ret", i)
		}
	}
	return refs
}

func summarizeArg(target *prog.Target, refs map[*prog.ResultArg]string,
	name string, arg prog.Arg) *runtimeCallArg {
	if arg == nil {
		return &runtimeCallArg{Name: name, Kind: "nil"}
	}
	ret := &runtimeCallArg{
		Name: name,
		Type: arg.Type().String(),
		Dir:  arg.Dir().String(),
		Kind: runtimeArgKind(arg),
		Size: arg.Size(),
	}
	switch a := arg.(type) {
	case *prog.ConstArg:
		val, _ := a.Value()
		ret.Value = uint64Ptr(val)
		ret.ValueNames = valueNames(target, arg.Type(), val)
	case *prog.ResultArg:
		ret.Value = uint64Ptr(a.Val)
		ret.ValueNames = valueNames(target, arg.Type(), a.Val)
		if a.Res != nil {
			ret.Ref = refs[a.Res]
			ret.Value = nil
		}
		if a.OpDiv != 0 {
			ret.OpDiv = uint64Ptr(a.OpDiv)
		}
		if a.OpAdd != 0 {
			ret.OpAdd = uint64Ptr(a.OpAdd)
		}
	case *prog.PointerArg:
		ret.Address = uint64Ptr(a.Address)
		if a.Res != nil {
			ret.Args = append(ret.Args, summarizeArg(target, refs, "", a.Res))
		}
	case *prog.DataArg:
		ret.DataSummary = summarizeDataArg(a)
	case *prog.GroupArg:
		ret.Args = summarizeGroupArgs(target, refs, a)
	case *prog.UnionArg:
		typ := a.Type().(*prog.UnionType)
		if a.Index >= 0 && a.Index < len(typ.Fields) {
			ret.Selected = typ.Fields[a.Index].Name
		}
		if a.Option != nil {
			ret.Args = append(ret.Args, summarizeArg(target, refs, ret.Selected, a.Option))
		}
	}
	return ret
}

func summarizeGroupArgs(target *prog.Target, refs map[*prog.ResultArg]string,
	arg *prog.GroupArg) []*runtimeCallArg {
	ret := make([]*runtimeCallArg, 0, len(arg.Inner))
	switch typ := arg.Type().(type) {
	case *prog.StructType:
		for i, inner := range arg.Inner {
			name := ""
			if i < len(typ.Fields) {
				name = typ.Fields[i].Name
			}
			ret = append(ret, summarizeArg(target, refs, name, inner))
		}
	case *prog.ArrayType:
		for i, inner := range arg.Inner {
			ret = append(ret, summarizeArg(target, refs, fmt.Sprintf("[%d]", i), inner))
		}
	}
	return ret
}

func summarizeDataArg(arg *prog.DataArg) *runtimeDataSummary {
	ret := &runtimeDataSummary{Size: arg.Size()}
	if arg.Dir() == prog.DirOut {
		ret.Output = true
		return ret
	}
	data := arg.Data()
	ret.Hash = hash.String(data)
	preview := data
	const maxPreviewBytes = 32
	if len(preview) > maxPreviewBytes {
		preview = preview[:maxPreviewBytes]
		ret.Truncated = true
	}
	ret.PreviewHex = hex.EncodeToString(preview)
	return ret
}

func runtimeArgKind(arg prog.Arg) string {
	switch arg.(type) {
	case *prog.ConstArg:
		switch arg.Type().(type) {
		case *prog.ConstType:
			return "const"
		case *prog.FlagsType:
			return "flags"
		case *prog.IntType:
			return "int"
		case *prog.LenType:
			return "len"
		case *prog.ProcType:
			return "proc"
		case *prog.CsumType:
			return "csum"
		default:
			return "const"
		}
	case *prog.ResultArg:
		return "result"
	case *prog.PointerArg:
		if _, ok := arg.Type().(*prog.VmaType); ok {
			return "vma"
		}
		return "ptr"
	case *prog.DataArg:
		return "data"
	case *prog.GroupArg:
		switch arg.Type().(type) {
		case *prog.StructType:
			return "struct"
		case *prog.ArrayType:
			return "array"
		default:
			return "group"
		}
	case *prog.UnionArg:
		return "union"
	default:
		return "unknown"
	}
}

func valueNames(target *prog.Target, typ prog.Type, value uint64) []string {
	switch t := typ.(type) {
	case *prog.FlagsType:
		return flagValueNames(target, t, value)
	case *prog.ConstType:
		if t.Val == value {
			return exactConstValueNames(target, value)
		}
	case *prog.ResourceType:
		return exactConstValueNames(target, value)
	}
	return nil
}

func flagValueNames(target *prog.Target, typ *prog.FlagsType, value uint64) []string {
	names := target.FlagsMap[typ.Name()]
	if len(names) == 0 {
		return nil
	}
	var ret []string
	if !typ.BitMask {
		for _, name := range names {
			if target.ConstMap[name] == value {
				ret = append(ret, name)
			}
		}
		return ret
	}
	remaining := value
	for _, name := range names {
		val := target.ConstMap[name]
		if val == 0 {
			if value == 0 {
				ret = append(ret, name)
			}
			continue
		}
		if remaining&val == val {
			ret = append(ret, name)
			remaining &^= val
		}
	}
	if len(ret) != 0 {
		return ret
	}
	return exactConstValueNames(target, value)
}

func exactConstValueNames(target *prog.Target, value uint64) []string {
	if value == 0 {
		return nil
	}
	const maxNames = 16
	var ret []string
	for _, c := range target.Consts {
		if c.Value == value {
			ret = append(ret, c.Name)
			if len(ret) == maxNames {
				break
			}
		}
	}
	return ret
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func int32Ptr(v int32) *int32 {
	return &v
}

func intPtr(v int) *int {
	return &v
}

func cloneInt64(v *int64) *int64 {
	if v == nil {
		return nil
	}
	return int64Ptr(*v)
}

type runtimeMismatchDifferenceIdentity struct {
	Kind         string
	Path         string
	OutputPolicy string
	Values       map[string]any
}

type runtimeMismatchCallIdentity struct {
	CallName    string
	Differences []runtimeMismatchDifferenceIdentity
}

func firstRuntimeMismatchCallIdentity(p *prog.Prog, mismatch *runtimeMismatch) (
	runtimeMismatchCallIdentity, int, bool) {
	if p == nil || mismatch == nil {
		return runtimeMismatchCallIdentity{}, -1, false
	}
	firstCall := len(p.Calls)
	for _, difference := range mismatch.StableDifferences {
		if difference.CallIndex == nil {
			continue
		}
		callIndex := *difference.CallIndex
		if callIndex >= 0 && callIndex < firstCall && callIndex < len(p.Calls) {
			firstCall = callIndex
		}
	}
	if firstCall == len(p.Calls) {
		return runtimeMismatchCallIdentity{}, -1, false
	}
	identity := runtimeMismatchCallIdentity{CallName: p.CallName(firstCall)}
	for _, difference := range mismatch.StableDifferences {
		if difference.CallIndex == nil || *difference.CallIndex != firstCall {
			continue
		}
		identity.Differences = append(identity.Differences, runtimeMismatchDifferenceIdentity{
			Kind:         difference.Kind,
			Path:         normalizeRuntimeDifferencePath(difference.Path),
			OutputPolicy: difference.OutputPolicy,
			Values:       difference.Values,
		})
	}
	sort.Slice(identity.Differences, func(i, j int) bool {
		left, right := identity.Differences[i], identity.Differences[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.OutputPolicy < right.OutputPolicy
	})
	return identity, firstCall, true
}

func (identity runtimeMismatchCallIdentity) matches(p *prog.Prog, mismatch *runtimeMismatch,
	callIndex int) bool {
	candidate, candidateCall, ok := firstRuntimeMismatchCallIdentity(p, mismatch)
	return ok && candidateCall == callIndex && reflect.DeepEqual(identity, candidate)
}

func (coord *multiRuntimeCoordinator) minimizeRuntimeMismatch(reproduced *programRun,
	baseline *runtimeMismatch, identity runtimeMismatchCallIdentity, callIndex int) {
	coord.mu.Lock()
	mode := coord.mismatchMinimizeMode
	coord.mu.Unlock()

	stopped := false
	minimized, minimizedCall := prog.Minimize(reproduced.Prog.Clone(), callIndex, mode,
		func(candidate *prog.Prog, candidateCall int) bool {
			if stopped || len(candidate.Calls) == 0 {
				return false
			}
			_, mismatch, ok := coord.executeMismatchCandidate(reproduced, candidate,
				mismatchMinimizeCandidateRuns)
			if !ok {
				stopped = true
				return false
			}
			return mismatch != nil && mismatch.Outcome == comparisonOutcomeMismatch &&
				identity.matches(candidate, mismatch, candidateCall)
		})
	if stopped || coord.closed() {
		return
	}

	finalRun, finalMismatch, ok := coord.executeMismatchCandidate(reproduced, minimized,
		mismatchReproRuns)
	if ok && finalMismatch != nil && finalMismatch.Outcome == comparisonOutcomeMismatch &&
		identity.matches(minimized, finalMismatch, minimizedCall) {
		finalRun.InitialResults = copyRuntimeResults(reproduced.InitialResults)
		log.Logf(0, "minimized runtime mismatch for program %d from %d to %d calls",
			reproduced.ParentID, len(reproduced.Prog.Calls), len(minimized.Calls))
		coord.saveRuntimeReport(finalRun, finalMismatch)
		return
	}
	if coord.closed() {
		return
	}
	log.Logf(1, "final minimized program for runtime mismatch %d did not reproduce; saving original repro",
		reproduced.ParentID)
	coord.saveRuntimeReport(reproduced, baseline)
}

func (coord *multiRuntimeCoordinator) executeMismatchCandidate(base *programRun, candidate *prog.Prog,
	reproRuns int) (*programRun, *runtimeMismatch, bool) {
	if coord.closed() {
		return nil, nil, false
	}
	run := &programRun{
		ID:         coord.allocateProgID(),
		ParentID:   base.ParentID,
		Stage:      runStageMinimize,
		Prog:       candidate.Clone(),
		ProgData:   candidate.Serialize(),
		Important:  true,
		Expected:   copyExpectedRuntimes(base.Expected),
		Samples:    map[string][]*runtimeResult{},
		ReproRuns:  reproRuns,
		Completion: make(chan runtimeComparisonCompletion, 1),
	}

	coord.mu.Lock()
	if coord.closed() {
		coord.mu.Unlock()
		return nil, nil, false
	}
	coord.runs[run.ID] = run
	queues := make(map[string]*queue.PlainQueue, len(run.Expected))
	for runtimeName := range run.Expected {
		queues[runtimeName] = coord.runtimeQueueLocked(runtimeName)
	}
	coord.mu.Unlock()

	for runtimeName, runtimeQueue := range queues {
		coord.submitReproSample(run, runtimeName, runtimeQueue)
	}
	select {
	case completion := <-run.Completion:
		return run, completion.Mismatch, true
	case <-coord.done:
		return run, nil, false
	}
}

func (coord *multiRuntimeCoordinator) closed() bool {
	select {
	case <-coord.done:
		return true
	default:
		return false
	}
}

func (coord *multiRuntimeCoordinator) enqueueMismatchRepro(initial *programRun) {
	reproID := coord.allocateProgID()
	expected := copyExpectedRuntimes(initial.Expected)
	reproRun := &programRun{
		ID:             reproID,
		ParentID:       initial.ID,
		Stage:          runStageRepro,
		Prog:           initial.Prog.Clone(),
		ProgData:       append([]byte(nil), initial.ProgData...),
		Important:      true,
		Expected:       expected,
		Samples:        map[string][]*runtimeResult{},
		ReproRuns:      mismatchReproRuns,
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
		coord.submitReproSample(reproRun, runtimeName, runtimeQueue)
	}
}

func (coord *multiRuntimeCoordinator) submitReproSample(run *programRun, runtimeName string,
	runtimeQueue *queue.PlainQueue) {
	req := &queue.Request{
		ProgID:    run.ID,
		Prog:      run.Prog.Clone(),
		Important: true,
	}
	fuzzer.EnableSyscallTrace(req)
	fuzzer.EnableSyscallOutputs(req)
	req.OnDone(func(r *queue.Request, res *queue.Result) bool {
		coord.recordResult(runtimeName, r, res)
		return true
	})
	coord.mu.Lock()
	consumer := coord.consumers[runtimeName]
	coord.mu.Unlock()
	if consumer != nil {
		consumer.enqueuePriority(req)
		return
	}
	runtimeQueue.Submit(req)
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
		for i := range copyResult.Calls {
			copyResult.Calls[i].Args = cloneRuntimeCallArgs(result.Calls[i].Args)
			copyResult.Calls[i].ReturnValue = cloneInt64(result.Calls[i].ReturnValue)
			copyResult.Calls[i].Outputs = cloneRuntimeOutputCaptures(result.Calls[i].Outputs)
		}
		ret[name] = &copyResult
	}
	return ret
}

func cloneRuntimeCallArgs(args []*runtimeCallArg) []*runtimeCallArg {
	if len(args) == 0 {
		return nil
	}
	ret := make([]*runtimeCallArg, 0, len(args))
	for _, arg := range args {
		if arg == nil {
			ret = append(ret, nil)
			continue
		}
		copyArg := *arg
		copyArg.ValueNames = append([]string(nil), arg.ValueNames...)
		if arg.Value != nil {
			copyArg.Value = uint64Ptr(*arg.Value)
		}
		if arg.Address != nil {
			copyArg.Address = uint64Ptr(*arg.Address)
		}
		if arg.OpDiv != nil {
			copyArg.OpDiv = uint64Ptr(*arg.OpDiv)
		}
		if arg.OpAdd != nil {
			copyArg.OpAdd = uint64Ptr(*arg.OpAdd)
		}
		if arg.DataSummary != nil {
			dataSummary := *arg.DataSummary
			copyArg.DataSummary = &dataSummary
		}
		copyArg.Args = cloneRuntimeCallArgs(arg.Args)
		ret = append(ret, &copyArg)
	}
	return ret
}

const (
	runtimeMismatchDirName = "runtime-mismatches"
	runtimeUnstableDirName = "runtime-unstable"
)

type mismatchStore struct {
	baseDir string
}

func newMismatchStore(workdir string) *mismatchStore {
	return newRuntimeReportStore(workdir, runtimeMismatchDirName)
}

func newUnstableStore(workdir string) *mismatchStore {
	return newRuntimeReportStore(workdir, runtimeUnstableDirName)
}

func newRuntimeReportStore(workdir, dirName string) *mismatchStore {
	if workdir == "" {
		return nil
	}
	return &mismatchStore{
		baseDir: filepath.Join(workdir, dirName),
	}
}

// Version 4 adds raw-preserving semantic output policies and canonical comparison values.
const storedMismatchReportFormatVersion = 4

type storedProgramCall struct {
	Index int               `json:"index"`
	Name  string            `json:"name,omitempty"`
	Args  []*runtimeCallArg `json:"args,omitempty"`
}

type storedMismatchReport struct {
	FormatVersion     int                                 `json:"format_version"`
	ParentProgID      int64                               `json:"parent_prog_id"`
	ReproProgID       int64                               `json:"repro_prog_id"`
	Outcome           comparisonOutcome                   `json:"outcome"`
	Reason            string                              `json:"reason"`
	Runtimes          []string                            `json:"runtimes"`
	ProgramCalls      []storedProgramCall                 `json:"program_calls,omitempty"`
	TraceFiles        []string                            `json:"trace_files,omitempty"`
	InitialResults    map[string]*runtimeResult           `json:"initial_results"`
	ReproSamples      map[string][]*runtimeResult         `json:"repro_samples"`
	Compared          map[string]*comparisonRuntimeResult `json:"compared"`
	StableDifferences []runtimeFieldDifference            `json:"stable_differences"`
	Triage            runtimeDiffTriage                   `json:"triage,omitempty"`
	UnstableFields    map[string][]string                 `json:"unstable_fields,omitempty"`
	InvalidSamples    map[string][]string                 `json:"invalid_samples,omitempty"`
	PartialSamples    map[string][]string                 `json:"partial_samples,omitempty"`
}

func storedProgramCallsFor(p *prog.Prog) []storedProgramCall {
	if p == nil {
		return nil
	}
	calls := make([]storedProgramCall, 0, len(p.Calls))
	for index := range p.Calls {
		calls = append(calls, storedProgramCall{
			Index: index,
			Name:  p.CallName(index),
			Args:  summarizeCallArgs(p, index),
		})
	}
	return calls
}

func compactRuntimeResultForReport(result *runtimeResult) *runtimeResult {
	if result == nil {
		return nil
	}
	compact := *result
	compact.Calls = make([]runtimeCallResult, len(result.Calls))
	for index, call := range result.Calls {
		compact.Calls[index] = call
		compact.Calls[index].Args = nil
		compact.Calls[index].Sctrace = ""
	}
	return &compact
}

func compactRuntimeResultsForReport(results map[string]*runtimeResult) map[string]*runtimeResult {
	if results == nil {
		return nil
	}
	compact := make(map[string]*runtimeResult, len(results))
	for runtimeName, result := range results {
		compact[runtimeName] = compactRuntimeResultForReport(result)
	}
	return compact
}

func compactRuntimeSamplesForReport(
	samples map[string][]*runtimeResult) map[string][]*runtimeResult {
	if samples == nil {
		return nil
	}
	compact := make(map[string][]*runtimeResult, len(samples))
	for runtimeName, runtimeSamples := range samples {
		compactSamples := make([]*runtimeResult, len(runtimeSamples))
		for index, result := range runtimeSamples {
			compactSamples[index] = compactRuntimeResultForReport(result)
		}
		compact[runtimeName] = compactSamples
	}
	return compact
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
	traceFiles := []string{}
	for runtimeName, result := range run.InitialResults {
		name := fmt.Sprintf("%s.initial.strace.log", sanitizeFileName(runtimeName))
		written, err := writeRuntimeTraceLog(dir, name, result)
		if err != nil {
			return "", err
		}
		if written {
			traceFiles = append(traceFiles, filepath.ToSlash(filepath.Join("logs", name)))
		}
	}
	for runtimeName, samples := range run.Samples {
		for sampleIndex, result := range samples {
			name := fmt.Sprintf("%s.sample%d.strace.log",
				sanitizeFileName(runtimeName), sampleIndex+1)
			written, err := writeRuntimeTraceLog(dir, name, result)
			if err != nil {
				return "", err
			}
			if written {
				traceFiles = append(traceFiles, filepath.ToSlash(filepath.Join("logs", name)))
			}
		}
	}
	sort.Strings(traceFiles)
	report := &storedMismatchReport{
		FormatVersion:     storedMismatchReportFormatVersion,
		ParentProgID:      run.ParentID,
		ReproProgID:       run.ID,
		Outcome:           mismatch.Outcome,
		Reason:            mismatch.Reason,
		Runtimes:          mismatch.Runtimes,
		ProgramCalls:      storedProgramCallsFor(run.Prog),
		TraceFiles:        traceFiles,
		InitialResults:    compactRuntimeResultsForReport(run.InitialResults),
		ReproSamples:      compactRuntimeSamplesForReport(run.Samples),
		Compared:          mismatch.Compared,
		StableDifferences: mismatch.StableDifferences,
		Triage:            mismatch.Triage,
		UnstableFields:    mismatch.UnstableFields,
		InvalidSamples:    mismatch.InvalidSamples,
		PartialSamples:    mismatch.PartialSamples,
	}
	data, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	if err := osutil.WriteFileAtomically(filepath.Join(dir, "report.json"), data); err != nil {
		return "", err
	}
	return dir, nil
}

func writeRuntimeTraceLog(dir, name string, result *runtimeResult) (bool, error) {
	if result == nil {
		return false, nil
	}
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
		return false, nil
	}
	if err := os.WriteFile(filepath.Join(dir, "logs", name), []byte(text.String()), 0o644); err != nil {
		return false, err
	}
	return true, nil
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
