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
	"github.com/google/syzkaller/prog"
)

type runtimeResult struct {
	Runtime    string              `json:"runtime"`
	Status     queue.Status        `json:"status"`
	StatusName string              `json:"status_name"`
	Err        string              `json:"err,omitempty"`
	Calls      []runtimeCallResult `json:"calls,omitempty"`
}

type runtimeCallResult struct {
	Index       int                     `json:"index"`
	Name        string                  `json:"name,omitempty"`
	Args        []*runtimeCallArg       `json:"args,omitempty"`
	Flags       flatrpc.CallFlag        `json:"flags"`
	Error       int32                   `json:"error"`
	ReturnValue *int64                  `json:"return_value,omitempty"`
	Outputs     []*runtimeOutputCapture `json:"outputs,omitempty"`
	Sctrace     string                  `json:"sctrace,omitempty"`
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

type runtimeDecodedOutput struct {
	Path        string              `json:"path"`
	Type        string              `json:"type"`
	Dir         string              `json:"dir"`
	Kind        string              `json:"kind"`
	Size        uint64              `json:"size,omitempty"`
	Value       *uint64             `json:"value,omitempty"`
	ValueNames  []string            `json:"value_names,omitempty"`
	RawHex      string              `json:"raw_hex,omitempty"`
	Truncated   bool                `json:"truncated,omitempty"`
	DataSummary *runtimeDataSummary `json:"data_summary,omitempty"`
}

type comparisonRuntimeCallResult struct {
	Index       int                     `json:"index"`
	Name        string                  `json:"name,omitempty"`
	Flags       flatrpc.CallFlag        `json:"flags"`
	Error       int32                   `json:"error"`
	ReturnValue *int64                  `json:"return_value,omitempty"`
	Outputs     []*runtimeOutputCapture `json:"outputs,omitempty"`
}

type comparisonRuntimeResult struct {
	Status queue.Status                  `json:"status"`
	Err    string                        `json:"err,omitempty"`
	Calls  []comparisonRuntimeCallResult `json:"calls,omitempty"`
}

type runtimeMismatch struct {
	Reason   string                              `json:"reason"`
	Runtimes []string                            `json:"runtimes"`
	Compared map[string]*comparisonRuntimeResult `json:"compared"`
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
			callResult.Args = summarizeCallArgs(req.Prog, i)
		}
		if call != nil {
			callResult.Flags = call.Flags
			callResult.Error = call.Error
			if call.ReturnValueValid {
				callResult.ReturnValue = int64Ptr(call.ReturnValue)
			}
			if req.Prog != nil && req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectOutputs != 0 {
				callResult.Outputs = summarizeCallOutputs(req.Prog, i, call.Outputs)
			}
			callResult.Sctrace = string(call.Sctrace)
		}
		ret.Calls = append(ret.Calls, callResult)
	}
	return ret
}

func (coord *multiRuntimeCoordinator) handleCompletedRun(run *programRun) {
	switch run.Stage {
	case runStageFuzz:
		mismatch := compareRuntimeResultsWithRules(run.Results, coord.noise.snapshot())
		if mismatch == nil {
			return
		}
		log.Logf(1, "program %d has cross-runtime result mismatch; scheduling repro", run.ID)
		coord.enqueueMismatchRepro(run)
	case runStageRepro:
		changed, err := coord.noise.learn(run.Samples)
		if err != nil {
			log.Logf(0, "failed to update runtime noise rules for program %d: %v",
				run.ParentID, err)
		} else if changed {
			log.Logf(1, "updated runtime noise rules after repro of program %d", run.ParentID)
		}
		rules := coord.noise.snapshot()
		results, unstableRuntime := stableRuntimeResults(run.Samples, rules)
		if unstableRuntime != "" {
			log.Logf(1, "program %d remains unstable within runtime %q after denoise",
				run.ParentID, unstableRuntime)
			return
		}
		mismatch := compareRuntimeResultsWithRules(results, rules)
		if mismatch == nil {
			return
		}
		if coord.store == nil {
			log.Logf(1, "confirmed runtime mismatch for program %d; no mismatch store configured",
				run.ParentID)
			return
		}
		path, err := coord.store.Save(run, mismatch, rules)
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
	return compareRuntimeResultsWithRules(results, noiseRuleFile{})
}

func compareRuntimeResultsWithRules(results map[string]*runtimeResult,
	rules noiseRuleFile) *runtimeMismatch {
	if len(results) < 2 {
		return nil
	}
	names := sortedRuntimeNames(results)
	compared := make(map[string]*comparisonRuntimeResult, len(results))
	for _, name := range names {
		result := results[name]
		if result.Status == queue.Unsupported {
			return nil
		}
		compared[name] = comparisonRuntimeResultForRules(result, rules)
	}
	reference := compared[names[0]]
	for _, name := range names[1:] {
		if !reflect.DeepEqual(reference, compared[name]) {
			return &runtimeMismatch{
				Reason:   "runtime results differ",
				Runtimes: names,
				Compared: compared,
			}
		}
	}
	return nil
}

func comparisonRuntimeResultFor(result *runtimeResult) *comparisonRuntimeResult {
	return comparisonRuntimeResultForRules(result, noiseRuleFile{})
}

func comparisonRuntimeResultForRules(result *runtimeResult,
	rules noiseRuleFile) *comparisonRuntimeResult {
	ret := &comparisonRuntimeResult{
		Status: result.Status,
		Err:    result.Err,
	}
	for _, call := range result.Calls {
		rule := rules.Syscalls[call.Name]
		errno := call.Error
		if rule.Ignore.Errno {
			errno = 0
		}
		var returnValue *int64
		if !rule.Ignore.ReturnValue {
			returnValue = cloneInt64(call.ReturnValue)
		}
		ret.Calls = append(ret.Calls, comparisonRuntimeCallResult{
			Index:       call.Index,
			Name:        call.Name,
			Flags:       call.Flags,
			Error:       errno,
			ReturnValue: returnValue,
			Outputs:     filterRuntimeOutputCaptures(call.Outputs, rule.Ignore.Outputs),
		})
	}
	return ret
}

func filterRuntimeOutputCaptures(captures []*runtimeOutputCapture,
	ignoredPaths []string) []*runtimeOutputCapture {
	ret := cloneRuntimeOutputCaptures(captures)
	if len(ret) == 0 || len(ignoredPaths) == 0 {
		return ret
	}
	ignored := make(map[string]bool, len(ignoredPaths))
	for _, path := range ignoredPaths {
		ignored[path] = true
	}
	for _, capture := range ret {
		if capture == nil {
			continue
		}
		values := capture.Values[:0]
		for _, value := range capture.Values {
			if value == nil || !ignored[value.Path] {
				values = append(values, value)
			}
		}
		if len(values) == 0 {
			capture.Values = nil
		} else {
			capture.Values = values
		}
	}
	return ret
}

func stableRuntimeResults(samples map[string][]*runtimeResult,
	rules noiseRuleFile) (map[string]*runtimeResult, string) {
	ret := make(map[string]*runtimeResult, len(samples))
	for runtimeName, runtimeSamples := range samples {
		if len(runtimeSamples) == 0 {
			return nil, runtimeName
		}
		baseline := comparisonRuntimeResultForRules(runtimeSamples[0], rules)
		for _, sample := range runtimeSamples[1:] {
			if !reflect.DeepEqual(baseline, comparisonRuntimeResultForRules(sample, rules)) {
				return nil, runtimeName
			}
		}
		ret[runtimeName] = runtimeSamples[0]
	}
	return ret, ""
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

func cloneInt64(v *int64) *int64 {
	if v == nil {
		return nil
	}
	return int64Ptr(*v)
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
	ReproSamples   map[string][]*runtimeResult         `json:"repro_samples"`
	NoiseRules     noiseRuleFile                       `json:"noise_rules"`
	Compared       map[string]*comparisonRuntimeResult `json:"compared"`
}

func (store *mismatchStore) Save(run *programRun, mismatch *runtimeMismatch,
	rules noiseRuleFile) (string, error) {
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
		ReproSamples:   run.Samples,
		NoiseRules:     rules,
		Compared:       mismatch.Compared,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), data, 0o644); err != nil {
		return "", err
	}
	for runtimeName, samples := range run.Samples {
		for sampleIndex, result := range samples {
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
			name := fmt.Sprintf("%s.sample%d.strace.log",
				sanitizeFileName(runtimeName), sampleIndex+1)
			if err := os.WriteFile(filepath.Join(dir, "logs", name),
				[]byte(text.String()), 0o644); err != nil {
				return "", err
			}
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
