// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

const (
	noiseRuleVersion  = 1
	noiseRuleFileName = "runtime-noise.json"
)

type noiseRuleFile struct {
	Version  int                         `json:"version"`
	Syscalls map[string]syscallNoiseRule `json:"syscalls,omitempty"`
}

type syscallNoiseRule struct {
	Ignore syscallNoiseIgnore `json:"ignore"`
}

type syscallNoiseIgnore struct {
	ReturnValue bool     `json:"return_value,omitempty"`
	Errno       bool     `json:"errno,omitempty"`
	Outputs     []string `json:"outputs,omitempty"`
}

type noiseFilter struct {
	mu    sync.RWMutex
	path  string
	rules noiseRuleFile
}

func newNoiseFilter(workdir string) *noiseFilter {
	filter := &noiseFilter{
		rules: noiseRuleFile{
			Version:  noiseRuleVersion,
			Syscalls: map[string]syscallNoiseRule{},
		},
	}
	if workdir == "" {
		return filter
	}
	filter.path = filepath.Join(workdir, noiseRuleFileName)
	if err := filter.load(); err != nil {
		log.Logf(0, "failed to load runtime noise rules from %s: %v", filter.path, err)
	}
	return filter
}

func (filter *noiseFilter) load() error {
	data, err := os.ReadFile(filter.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rules noiseRuleFile
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	if rules.Version != noiseRuleVersion {
		return fmt.Errorf("unsupported version %d", rules.Version)
	}
	normalizeNoiseRules(&rules)
	filter.rules = rules
	return nil
}

func (filter *noiseFilter) learn(samples map[string][]*runtimeResult) (bool, error) {
	learned := learnNoiseRules(samples)
	filter.mu.Lock()
	defer filter.mu.Unlock()
	next := cloneNoiseRules(filter.rules)
	if !mergeNoiseRules(&next, learned) {
		return false, nil
	}
	if filter.path == "" {
		filter.rules = next
		return true, nil
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	if err := osutil.WriteFileAtomically(filter.path, data); err != nil {
		return false, err
	}
	filter.rules = next
	return true, nil
}

func (filter *noiseFilter) snapshot() noiseRuleFile {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	return cloneNoiseRules(filter.rules)
}

func learnNoiseRules(samples map[string][]*runtimeResult) noiseRuleFile {
	rules := noiseRuleFile{
		Version:  noiseRuleVersion,
		Syscalls: map[string]syscallNoiseRule{},
	}
	for _, runtimeSamples := range samples {
		if len(runtimeSamples) < 2 {
			continue
		}
		baseline := runtimeSamples[0]
		for _, sample := range runtimeSamples[1:] {
			learnNoiseFromPair(&rules, baseline, sample)
		}
	}
	normalizeNoiseRules(&rules)
	return rules
}

func learnNoiseFromPair(rules *noiseRuleFile, left, right *runtimeResult) {
	if left == nil || right == nil {
		return
	}
	count := min(len(left.Calls), len(right.Calls))
	for i := 0; i < count; i++ {
		leftCall := &left.Calls[i]
		rightCall := &right.Calls[i]
		if leftCall.Name == "" || leftCall.Name != rightCall.Name {
			continue
		}
		rule := rules.Syscalls[leftCall.Name]
		if leftCall.Error != rightCall.Error {
			rule.Ignore.Errno = true
		}
		if !reflect.DeepEqual(leftCall.ReturnValue, rightCall.ReturnValue) {
			rule.Ignore.ReturnValue = true
		}
		leftOutputs := decodedOutputsByPath(leftCall.Outputs)
		rightOutputs := decodedOutputsByPath(rightCall.Outputs)
		for path, leftOutput := range leftOutputs {
			if !reflect.DeepEqual(leftOutput, rightOutputs[path]) {
				rule.Ignore.Outputs = append(rule.Ignore.Outputs, path)
			}
		}
		for path := range rightOutputs {
			if _, ok := leftOutputs[path]; !ok {
				rule.Ignore.Outputs = append(rule.Ignore.Outputs, path)
			}
		}
		if rule.Ignore.ReturnValue || rule.Ignore.Errno || len(rule.Ignore.Outputs) != 0 {
			rules.Syscalls[leftCall.Name] = rule
		}
	}
}

func decodedOutputsByPath(captures []*runtimeOutputCapture) map[string]*runtimeDecodedOutput {
	ret := map[string]*runtimeDecodedOutput{}
	for _, capture := range captures {
		if capture == nil {
			continue
		}
		for _, output := range capture.Values {
			if output != nil && output.Path != "" {
				ret[output.Path] = output
			}
		}
	}
	return ret
}

func mergeNoiseRules(dst *noiseRuleFile, src noiseRuleFile) bool {
	if dst.Version == 0 {
		dst.Version = noiseRuleVersion
	}
	if dst.Syscalls == nil {
		dst.Syscalls = map[string]syscallNoiseRule{}
	}
	changed := false
	for name, srcRule := range src.Syscalls {
		dstRule := dst.Syscalls[name]
		if srcRule.Ignore.ReturnValue && !dstRule.Ignore.ReturnValue {
			dstRule.Ignore.ReturnValue = true
			changed = true
		}
		if srcRule.Ignore.Errno && !dstRule.Ignore.Errno {
			dstRule.Ignore.Errno = true
			changed = true
		}
		outputs := make(map[string]bool, len(dstRule.Ignore.Outputs))
		for _, path := range dstRule.Ignore.Outputs {
			outputs[path] = true
		}
		for _, path := range srcRule.Ignore.Outputs {
			if path != "" && !outputs[path] {
				dstRule.Ignore.Outputs = append(dstRule.Ignore.Outputs, path)
				outputs[path] = true
				changed = true
			}
		}
		if len(dstRule.Ignore.Outputs) != 0 || dstRule.Ignore.ReturnValue || dstRule.Ignore.Errno {
			dst.Syscalls[name] = dstRule
		}
	}
	if changed {
		normalizeNoiseRules(dst)
	}
	return changed
}

func normalizeNoiseRules(rules *noiseRuleFile) {
	if rules.Syscalls == nil {
		rules.Syscalls = map[string]syscallNoiseRule{}
	}
	for name, rule := range rules.Syscalls {
		oldOutputs := rule.Ignore.Outputs
		outputs := make(map[string]bool, len(oldOutputs))
		rule.Ignore.Outputs = nil
		for _, path := range oldOutputs {
			if path != "" {
				outputs[path] = true
			}
		}
		for path := range outputs {
			rule.Ignore.Outputs = append(rule.Ignore.Outputs, path)
		}
		sort.Strings(rule.Ignore.Outputs)
		if !rule.Ignore.ReturnValue && !rule.Ignore.Errno && len(rule.Ignore.Outputs) == 0 {
			delete(rules.Syscalls, name)
			continue
		}
		rules.Syscalls[name] = rule
	}
}

func cloneNoiseRules(rules noiseRuleFile) noiseRuleFile {
	ret := noiseRuleFile{
		Version:  rules.Version,
		Syscalls: make(map[string]syscallNoiseRule, len(rules.Syscalls)),
	}
	for name, rule := range rules.Syscalls {
		rule.Ignore.Outputs = append([]string(nil), rule.Ignore.Outputs...)
		ret.Syscalls[name] = rule
	}
	return ret
}
