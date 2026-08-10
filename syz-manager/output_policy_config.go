// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/prog"
)

type runtimeOutputPolicySelector struct {
	CallName    string `json:"call_name,omitempty"`
	CaptureType string `json:"capture_type,omitempty"`
	OutputType  string `json:"output_type,omitempty"`
	Field       string `json:"field,omitempty"`
	Path        string `json:"path,omitempty"`
}

type runtimeOutputPolicyRule struct {
	ID       string                      `json:"id"`
	Selector runtimeOutputPolicySelector `json:"selector"`
	Policy   prog.OutputPolicy           `json:"policy"`
}

type runtimeOutputPolicyFile struct {
	FormatVersion int                       `json:"format_version"`
	Rules         []runtimeOutputPolicyRule `json:"rules"`
}

type runtimeOutputPolicyStore struct {
	rules []runtimeOutputPolicyRule
	hash  string
}

func loadRuntimeOutputPolicies(filePath string) (*runtimeOutputPolicyStore, error) {
	store := &runtimeOutputPolicyStore{}
	if filePath == "" {
		return store, nil
	}
	data, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var file runtimeOutputPolicyFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode %s: %w", filePath, err)
	}
	if file.FormatVersion != 0 && file.FormatVersion != 1 {
		return nil, fmt.Errorf("unsupported format_version %d in %s", file.FormatVersion, filePath)
	}
	seenIDs := make(map[string]bool)
	seenSelectors := make(map[string]bool)
	for index, rule := range file.Rules {
		if rule.ID == "" {
			return nil, fmt.Errorf("output policy rule %d in %s has no id", index, filePath)
		}
		if seenIDs[rule.ID] {
			return nil, fmt.Errorf("duplicate output policy rule id %q", rule.ID)
		}
		seenIDs[rule.ID] = true
		if rule.Policy.Kind == "" {
			return nil, fmt.Errorf("output policy rule %q has no policy kind", rule.ID)
		}
		if err := prog.ValidateOutputPolicy(rule.Policy); err != nil {
			return nil, fmt.Errorf("output policy rule %q: %w", rule.ID, err)
		}
		if rule.Selector == (runtimeOutputPolicySelector{}) {
			return nil, fmt.Errorf("output policy rule %q has an empty selector", rule.ID)
		}
		if rule.Selector.Path != "" {
			if _, err := path.Match(rule.Selector.Path, "probe"); err != nil {
				return nil, fmt.Errorf("output policy rule %q has invalid path pattern: %w",
					rule.ID, err)
			}
		}
		selectorData, _ := json.Marshal(rule.Selector)
		selectorKey := string(selectorData)
		if seenSelectors[selectorKey] {
			return nil, fmt.Errorf("duplicate output policy selector in rule %q", rule.ID)
		}
		seenSelectors[selectorKey] = true
		store.rules = append(store.rules, rule)
	}
	sum := sha256.Sum256(data)
	store.hash = hex.EncodeToString(sum[:])
	return store, nil
}

func (coord *multiRuntimeCoordinator) configureRuntimeOutputPolicies(filePath string) error {
	if filePath == "" && coord.store != nil {
		filePath = filepath.Join(filepath.Dir(coord.store.baseDir), "runtime-output-policy.json")
	} else if filePath != "" && !filepath.IsAbs(filePath) && coord.store != nil {
		filePath = filepath.Join(filepath.Dir(coord.store.baseDir), filePath)
	}
	store, err := loadRuntimeOutputPolicies(filePath)
	if err != nil {
		return err
	}
	coord.mu.Lock()
	coord.outputPolicies = store
	coord.mu.Unlock()
	return nil
}

func applyRuntimeOutputPolicies(callName string, captures []*runtimeOutputCapture,
	store *runtimeOutputPolicyStore) {
	if store == nil {
		return
	}
	for _, capture := range captures {
		if capture == nil {
			continue
		}
		for _, output := range capture.Values {
			if output == nil {
				continue
			}
			matchedID := ""
			for _, rule := range store.rules {
				if !rule.Selector.matches(callName, capture, output) {
					continue
				}
				if matchedID != "" && rule.Policy.Kind != "" &&
					rule.Policy.Kind != output.OutputPolicy.Kind {
					output.NormalizationErr = fmt.Sprintf(
						"conflicting external output policies %q and %q", matchedID, rule.ID)
					break
				}
				output.OutputPolicy = prog.MergeOutputPolicy(output.OutputPolicy, rule.Policy)
				output.PolicySource = "external:" + rule.ID
				if rule.Policy.Scope != "" {
					output.PolicyScope = runtimeOutputPolicyScope(output.Path, rule.Policy.Scope)
				} else if output.PolicyScope == "" || matchedID == "" {
					output.PolicyScope = output.Path
				}
				matchedID = rule.ID
			}
		}
	}
}

func (selector runtimeOutputPolicySelector) matches(callName string,
	capture *runtimeOutputCapture, output *runtimeDecodedOutput) bool {
	if selector.CallName != "" && selector.CallName != callName {
		return false
	}
	if selector.CaptureType != "" && selector.CaptureType != capture.Type {
		return false
	}
	if selector.OutputType != "" && selector.OutputType != output.Type {
		return false
	}
	if selector.Field != "" && selector.Field != runtimeOutputFieldName(output.Path) {
		return false
	}
	if selector.Path != "" {
		matched, _ := path.Match(selector.Path, output.Path)
		if !matched {
			return false
		}
	}
	return true
}

func runtimeOutputFieldName(outputPath string) string {
	if index := strings.LastIndexByte(outputPath, '.'); index != -1 {
		return outputPath[index+1:]
	}
	return outputPath
}
