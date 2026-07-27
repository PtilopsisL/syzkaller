// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

type kernelVersion struct {
	Major int
	Minor int
}

var kernelVersionRE = regexp.MustCompile(`(?:^|[^0-9])v?([0-9]+)\.([0-9]+)(?:[.-]|$)`)

func parseKernelVersion(text string) (kernelVersion, bool) {
	match := kernelVersionRE.FindStringSubmatch(strings.TrimSpace(text))
	if len(match) != 3 {
		return kernelVersion{}, false
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return kernelVersion{}, false
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return kernelVersion{}, false
	}
	return kernelVersion{Major: major, Minor: minor}, true
}

func (version kernelVersion) less(other kernelVersion) bool {
	if version.Major != other.Major {
		return version.Major < other.Major
	}
	return version.Minor < other.Minor
}

func runtimeVersionForResult(result *runtimeResult) (kernelVersion, bool) {
	if result == nil {
		return kernelVersion{}, false
	}
	if text := strings.TrimSpace(result.RuntimeVersion); text != "" {
		return parseKernelVersion(text)
	}
	return parseKernelVersion(result.Runtime)
}

type versionRulePredicate string

const (
	versionRuleAdditiveBits versionRulePredicate = "additive_bits"
	versionRuleValueSet     versionRulePredicate = "value_set"
)

type versionCompatibilityRule struct {
	ID           string
	CallNames    []string
	Kind         string
	PathPattern  string
	IntroducedIn kernelVersion
	Predicate    versionRulePredicate
	AdditiveMask uint64
	OutputType   string
	OutputDir    string
	OutputKind   string
	OutputSize   uint64
	OlderValues  []int64
	NewerValues  []int64
}

// These rules intentionally contain only high-confidence UAPI evolution. A
// value that does not match a rule, or a runtime whose version is unknown, is
// kept as a normal mismatch.
var defaultVersionCompatibilityRules = []versionCompatibilityRule{
	{
		ID:           "io_uring.params.features.additive-v6.4",
		CallNames:    []string{"io_uring_setup", "syz_io_uring_setup"},
		Kind:         "output",
		PathPattern:  "calls[*].outputs.arg[1].features",
		IntroducedIn: kernelVersion{Major: 6, Minor: 4},
		Predicate:    versionRuleAdditiveBits,
		AdditiveMask: 1 << 13,
		OutputType:   "int32",
		OutputDir:    "out",
		OutputKind:   "int",
		OutputSize:   4,
	},
}

var runtimeCallPathRE = regexp.MustCompile(`calls\[[0-9]+\]`)

func normalizeRuntimeDifferencePath(path string) string {
	return runtimeCallPathRE.ReplaceAllString(path, "calls[*]")
}

func filterExpectedVersionDifferences(differences []runtimeFieldDifference,
	samples map[string][]*runtimeResult, rules []versionCompatibilityRule) (
	[]runtimeFieldDifference, []runtimeExpectedDifference) {
	if len(differences) == 0 || len(samples) == 0 || len(rules) == 0 {
		return differences, nil
	}
	unexpected := make([]runtimeFieldDifference, 0, len(differences))
	expected := make([]runtimeExpectedDifference, 0)
	for _, difference := range differences {
		matched := ""
		for _, rule := range rules {
			if matchesVersionCompatibilityRule(rule, difference, samples) {
				matched = rule.ID
				break
			}
		}
		if matched == "" {
			unexpected = append(unexpected, difference)
			continue
		}
		expected = append(expected, runtimeExpectedDifference{Rule: matched, Difference: difference})
	}
	return unexpected, expected
}

func matchesVersionCompatibilityRule(rule versionCompatibilityRule, difference runtimeFieldDifference,
	samples map[string][]*runtimeResult) bool {
	if difference.Kind != rule.Kind ||
		normalizeRuntimeDifferencePath(difference.Path) != rule.PathPattern ||
		len(samples) < 2 || rule.IntroducedIn.Major <= 0 || rule.IntroducedIn.Minor < 0 {
		return false
	}
	if len(rule.CallNames) != 0 && !containsString(rule.CallNames, difference.CallName) {
		return false
	}
	if len(difference.Values) != len(samples) {
		return false
	}
	type versionedValue struct {
		value uint64
	}
	var older, newer []versionedValue
	for runtimeName, runtimeSamples := range samples {
		if len(runtimeSamples) == 0 || difference.Values[runtimeName] == nil {
			return false
		}
		version, ok := runtimeVersionForResult(runtimeSamples[0])
		if !ok {
			return false
		}
		value, ok := numericDifferenceValue(difference.Values[runtimeName])
		if !ok {
			return false
		}
		if rule.OutputType != "" {
			metadata, ok := runtimeDifferenceOutputMetadata(difference.Values[runtimeName])
			if !ok || metadata.Type != rule.OutputType || metadata.Dir != rule.OutputDir ||
				metadata.Kind != rule.OutputKind || (rule.OutputSize != 0 && metadata.Size != rule.OutputSize) {
				return false
			}
		}
		entry := versionedValue{value: value}
		if version.less(rule.IntroducedIn) {
			older = append(older, entry)
		} else {
			newer = append(newer, entry)
		}
	}
	if len(older) == 0 || len(newer) == 0 {
		return false
	}
	switch rule.Predicate {
	case versionRuleAdditiveBits:
		base := older[0].value
		for _, entry := range older[1:] {
			if entry.value != base {
				return false
			}
		}
		for _, entry := range newer {
			delta := entry.value &^ base
			if delta == 0 || entry.value&base != base || delta&^rule.AdditiveMask != 0 {
				return false
			}
		}
	case versionRuleValueSet:
		for _, entry := range older {
			value, ok := signedDifferenceValue(entry.value)
			if !ok || !containsInt64(rule.OlderValues, value) {
				return false
			}
		}
		for _, entry := range newer {
			value, ok := signedDifferenceValue(entry.value)
			if !ok || !containsInt64(rule.NewerValues, value) {
				return false
			}
		}
	default:
		return false
	}
	return true
}

type runtimeOutputDifferenceMetadata struct {
	Type string
	Dir  string
	Kind string
	Size uint64
}

func runtimeDifferenceOutputMetadata(value any) (runtimeOutputDifferenceMetadata, bool) {
	switch value := value.(type) {
	case runtimeDecodedOutput:
		return runtimeOutputDifferenceMetadata{Type: value.Type, Dir: value.Dir, Kind: value.Kind, Size: value.Size}, true
	case *runtimeDecodedOutput:
		if value == nil {
			return runtimeOutputDifferenceMetadata{}, false
		}
		return runtimeOutputDifferenceMetadata{Type: value.Type, Dir: value.Dir, Kind: value.Kind, Size: value.Size}, true
	case map[string]any:
		typ, typeOK := value["type"].(string)
		dir, dirOK := value["dir"].(string)
		kind, kindOK := value["kind"].(string)
		size, sizeOK := numericDifferenceValue(value["size"])
		if !typeOK || !dirOK || !kindOK || !sizeOK {
			return runtimeOutputDifferenceMetadata{}, false
		}
		return runtimeOutputDifferenceMetadata{Type: typ, Dir: dir, Kind: kind, Size: size}, true
	default:
		return runtimeOutputDifferenceMetadata{}, false
	}
}

func numericDifferenceValue(value any) (uint64, bool) {
	switch value := value.(type) {
	case runtimeDecodedOutput:
		if value.Value == nil {
			return 0, false
		}
		return *value.Value, true
	case *runtimeDecodedOutput:
		if value == nil || value.Value == nil {
			return 0, false
		}
		return *value.Value, true
	case map[string]any:
		return numericDifferenceValue(value["value"])
	case json.Number:
		parsed, err := strconv.ParseUint(string(value), 10, 64)
		return parsed, err == nil
	case uint:
		return uint64(value), true
	case uint8:
		return uint64(value), true
	case uint16:
		return uint64(value), true
	case uint32:
		return uint64(value), true
	case uint64:
		return value, true
	case int:
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	case int8:
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	case int16:
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	case int32:
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	case int64:
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	case float64:
		if value < 0 || value >= float64(1<<63) || value != float64(uint64(value)) {
			return 0, false
		}
		return uint64(value), true
	default:
		return 0, false
	}
}

func signedDifferenceValue(value any) (int64, bool) {
	unsigned, ok := numericDifferenceValue(value)
	if !ok || unsigned > uint64(1<<63-1) {
		return 0, false
	}
	return int64(unsigned), true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsInt64(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
