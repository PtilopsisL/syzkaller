// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// runtimeDiffLabel is deliberately a human-facing classification.  The
// comparison code does not infer that a label is correct; it only attaches a
// reviewed label to a matching difference when one was supplied.
type runtimeDiffLabel string

const (
	runtimeDiffExpectedVersion runtimeDiffLabel = "expected_version_difference"
	runtimeDiffEnvironment     runtimeDiffLabel = "environment_difference"
	runtimeDiffInfrastructure  runtimeDiffLabel = "infrastructure_or_incomplete"
	runtimeDiffKernelBug       runtimeDiffLabel = "kernel_bug_candidate"
	runtimeDiffUnknown         runtimeDiffLabel = "unknown"
)

var validRuntimeDiffLabels = map[runtimeDiffLabel]bool{
	runtimeDiffExpectedVersion: true,
	runtimeDiffEnvironment:     true,
	runtimeDiffInfrastructure:  true,
	runtimeDiffKernelBug:       true,
	runtimeDiffUnknown:         true,
}

// runtimeDiffLabelScope limits a manual annotation to the runtime set for
// which it was reviewed.  An empty scope is intentionally allowed for a label
// that is known to be independent of the runtime set, but users should prefer
// an explicit scope for version-related labels.
type runtimeDiffLabelScope struct {
	RuntimeNames    []string          `json:"runtime_names,omitempty"`
	RuntimeVersions map[string]string `json:"runtime_versions,omitempty"`
}

type runtimeDiffLabelEntry struct {
	ID          string                `json:"id"`
	Label       runtimeDiffLabel      `json:"label"`
	Fingerprint string                `json:"fingerprint,omitempty"`
	Signature   string                `json:"signature,omitempty"`
	Scope       runtimeDiffLabelScope `json:"scope,omitempty"`
	Note        string                `json:"note,omitempty"`
}

type runtimeDiffLabelFile struct {
	FormatVersion int                     `json:"format_version"`
	Labels        []runtimeDiffLabelEntry `json:"labels"`
}

type runtimeDiffLabelStore struct {
	labels []runtimeDiffLabelEntry
}

type runtimeDiffTriage struct {
	FirstFingerprint string         `json:"first_fingerprint,omitempty"`
	FirstSignature   string         `json:"first_signature,omitempty"`
	LabelCounts      map[string]int `json:"label_counts,omitempty"`
}

func summarizeRuntimeDiffTriage(differences []runtimeFieldDifference) runtimeDiffTriage {
	var ret runtimeDiffTriage
	if len(differences) != 0 {
		ret.FirstFingerprint = differences[0].Fingerprint
		ret.FirstSignature = differences[0].Signature
	}
	for _, difference := range differences {
		if difference.TriageLabel == "" {
			continue
		}
		if ret.LabelCounts == nil {
			ret.LabelCounts = make(map[string]int)
		}
		ret.LabelCounts[difference.TriageLabel]++
	}
	return ret
}

var runtimeCallPathRE = regexp.MustCompile(`calls\[[0-9]+\]`)

func normalizeRuntimeDifferencePath(path string) string {
	return runtimeCallPathRE.ReplaceAllString(path, "calls[*]")
}

func loadRuntimeDiffLabels(path string) (*runtimeDiffLabelStore, error) {
	store := &runtimeDiffLabelStore{}
	if path == "" {
		return store, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var file runtimeDiffLabelFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if file.FormatVersion != 0 && file.FormatVersion != 1 {
		return nil, fmt.Errorf("unsupported format_version %d in %s", file.FormatVersion, path)
	}
	seenIDs := make(map[string]bool)
	for index, label := range file.Labels {
		if label.ID == "" {
			return nil, fmt.Errorf("label %d in %s has no id", index, path)
		}
		if seenIDs[label.ID] {
			return nil, fmt.Errorf("duplicate label id %q in %s", label.ID, path)
		}
		seenIDs[label.ID] = true
		if !validRuntimeDiffLabels[label.Label] {
			return nil, fmt.Errorf("label %q has unsupported classification %q", label.ID, label.Label)
		}
		if label.Fingerprint == "" && label.Signature == "" {
			return nil, fmt.Errorf("label %q has neither fingerprint nor signature", label.ID)
		}
		label.Scope.RuntimeNames = append([]string(nil), label.Scope.RuntimeNames...)
		sort.Strings(label.Scope.RuntimeNames)
		store.labels = append(store.labels, label)
	}
	return store, nil
}

func (coord *multiRuntimeCoordinator) configureRuntimeDiffLabels(path string) error {
	if path == "" && coord.store != nil {
		// Keep the default outside runtime-mismatches so label edits do not look
		// like generated reports and are easy to back up with the workdir.
		path = filepath.Join(filepath.Dir(coord.store.baseDir), "runtime-diff-labels.json")
	} else if path != "" && !filepath.IsAbs(path) && coord.store != nil {
		path = filepath.Join(filepath.Dir(coord.store.baseDir), path)
	}
	store, err := loadRuntimeDiffLabels(path)
	if err != nil {
		return err
	}
	coord.mu.Lock()
	coord.diffLabels = store
	coord.mu.Unlock()
	return nil
}

func (store *runtimeDiffLabelStore) match(difference runtimeFieldDifference,
	samples map[string][]*runtimeResult) *runtimeDiffLabelEntry {
	if store == nil {
		return nil
	}
	for index := range store.labels {
		label := &store.labels[index]
		if label.Fingerprint != "" && label.Fingerprint != difference.Fingerprint {
			continue
		}
		if label.Signature != "" && label.Signature != difference.Signature {
			continue
		}
		if !runtimeDiffLabelScopeMatches(label.Scope, samples) {
			continue
		}
		return label
	}
	return nil
}

func runtimeDiffLabelScopeMatches(scope runtimeDiffLabelScope,
	samples map[string][]*runtimeResult) bool {
	names := sortedRuntimeSampleNames(samples)
	if len(scope.RuntimeNames) != 0 {
		want := append([]string(nil), scope.RuntimeNames...)
		sort.Strings(want)
		if !reflectStringSlicesEqual(names, want) {
			return false
		}
	}
	if len(scope.RuntimeVersions) == 0 {
		return true
	}
	for name, want := range scope.RuntimeVersions {
		runtimeSamples := samples[name]
		if len(runtimeSamples) == 0 || runtimeSamples[0] == nil {
			return false
		}
		got := strings.TrimSpace(runtimeSamples[0].RuntimeVersion)
		if got == "" {
			got = strings.TrimSpace(runtimeSamples[0].Runtime)
		}
		if got != strings.TrimSpace(want) {
			return false
		}
	}
	return true
}

func reflectStringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// annotateRuntimeDifferences computes both a semantic signature and an exact
// observation fingerprint.  Signatures intentionally omit runtime-specific
// values so a reviewer can reuse a label for a new kernel pair; fingerprints
// retain the observed values and are safer for narrow labels.
func annotateRuntimeDifferences(differences []runtimeFieldDifference,
	samples map[string][]*runtimeResult, labels *runtimeDiffLabelStore) {
	for index := range differences {
		difference := &differences[index]
		signaturePayload := runtimeDiffSignaturePayload{
			Kind:         difference.Kind,
			Path:         normalizeRuntimeDifferencePath(difference.Path),
			CallName:     difference.CallName,
			OutputPolicy: difference.OutputPolicy,
			Args:         runtimeDiffCallArgs(*difference, samples),
		}
		difference.Signature = hashRuntimeDiffPayload("signature", signaturePayload)
		values := runtimeDiffObservedValues(difference.Values)
		difference.Fingerprint = hashRuntimeDiffPayload("fingerprint", struct {
			Signature string   `json:"signature"`
			Values    []string `json:"values"`
		}{difference.Signature, values})
		if label := labels.match(*difference, samples); label != nil {
			difference.TriageLabel = string(label.Label)
			difference.TriageLabelID = label.ID
			difference.TriageNote = label.Note
		}
	}
}

type runtimeDiffSignaturePayload struct {
	Kind         string                   `json:"kind"`
	Path         string                   `json:"path"`
	CallName     string                   `json:"call_name,omitempty"`
	OutputPolicy string                   `json:"output_policy,omitempty"`
	Args         []runtimeDiffArgIdentity `json:"args,omitempty"`
}

type runtimeDiffArgIdentity struct {
	Name     string                   `json:"name,omitempty"`
	Type     string                   `json:"type,omitempty"`
	Dir      string                   `json:"dir,omitempty"`
	Kind     string                   `json:"kind,omitempty"`
	Value    *uint64                  `json:"value,omitempty"`
	Size     uint64                   `json:"size,omitempty"`
	Selected string                   `json:"selected,omitempty"`
	Ref      string                   `json:"ref,omitempty"`
	OpDiv    *uint64                  `json:"op_div,omitempty"`
	OpAdd    *uint64                  `json:"op_add,omitempty"`
	DataSize uint64                   `json:"data_size,omitempty"`
	DataHash string                   `json:"data_hash,omitempty"`
	DataOut  bool                     `json:"data_out,omitempty"`
	Args     []runtimeDiffArgIdentity `json:"args,omitempty"`
}

func runtimeDiffCallArgs(difference runtimeFieldDifference,
	samples map[string][]*runtimeResult) []runtimeDiffArgIdentity {
	if difference.CallIndex == nil {
		return nil
	}
	names := sortedRuntimeSampleNames(samples)
	var fallback []runtimeDiffArgIdentity
	found := false
	for _, name := range names {
		for _, sample := range samples[name] {
			if sample == nil {
				continue
			}
			for _, call := range sample.Calls {
				if call.Index != *difference.CallIndex {
					continue
				}
				args := make([]runtimeDiffArgIdentity, 0, len(call.Args))
				for _, arg := range call.Args {
					args = append(args, runtimeDiffArgIdentityFor(arg))
				}
				if !found {
					fallback = args
					found = true
				}
				// Older executor/result paths may omit args in one sample. Prefer
				// a later sample that still carries the program arguments.
				if len(args) != 0 {
					return args
				}
			}
		}
	}
	return fallback
}

func runtimeDiffArgIdentityFor(arg *runtimeCallArg) runtimeDiffArgIdentity {
	if arg == nil {
		return runtimeDiffArgIdentity{}
	}
	ret := runtimeDiffArgIdentity{
		Name: arg.Name, Type: arg.Type, Dir: arg.Dir, Kind: arg.Kind,
		Size: arg.Size, Selected: arg.Selected, Ref: arg.Ref,
		DataOut: arg.DataSummary != nil && arg.DataSummary.Output,
	}
	if arg.Value != nil {
		ret.Value = uint64Ptr(*arg.Value)
	}
	if arg.OpDiv != nil {
		ret.OpDiv = uint64Ptr(*arg.OpDiv)
	}
	if arg.OpAdd != nil {
		ret.OpAdd = uint64Ptr(*arg.OpAdd)
	}
	if arg.DataSummary != nil {
		ret.DataSize = arg.DataSummary.Size
		if !arg.DataSummary.Output {
			ret.DataHash = arg.DataSummary.Hash
		}
	}
	for _, child := range arg.Args {
		ret.Args = append(ret.Args, runtimeDiffArgIdentityFor(child))
	}
	return ret
}

func runtimeDiffObservedValues(values map[string]any) []string {
	ret := make([]string, 0, len(values))
	for name, value := range values {
		data, err := json.Marshal(struct {
			Runtime string `json:"runtime"`
			Value   any    `json:"value"`
		}{name, value})
		if err != nil {
			ret = append(ret, fmt.Sprintf("%s:<unencodable:%T>", name, value))
			continue
		}
		ret = append(ret, string(data))
	}
	sort.Strings(ret)
	return ret
}

func hashRuntimeDiffPayload(kind string, payload any) string {
	data, err := json.Marshal(struct {
		Kind    string `json:"kind"`
		Payload any    `json:"payload"`
	}{kind, payload})
	if err != nil {
		// All payload types above are JSON encodable.  Keep a non-empty value if
		// a future field violates that assumption, so the report remains useful.
		data = []byte(fmt.Sprintf("%s:%T", kind, payload))
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
