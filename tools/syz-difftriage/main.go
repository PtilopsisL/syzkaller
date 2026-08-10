// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-difftriage records a human classification for a stored multi-runtime
// mismatch. It deliberately never edits the mismatch report: labels are
// appended to a separate file that syz-manager reads at startup.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type diffLabel string

const (
	diffExpectedVersion diffLabel = "expected_version_difference"
	diffEnvironment     diffLabel = "environment_difference"
	diffInfrastructure  diffLabel = "infrastructure_or_incomplete"
	diffKernelBug       diffLabel = "kernel_bug_candidate"
	diffUnknown         diffLabel = "unknown"
)

var validLabels = map[diffLabel]bool{
	diffExpectedVersion: true,
	diffEnvironment:     true,
	diffInfrastructure:  true,
	diffKernelBug:       true,
	diffUnknown:         true,
}

type labelScope struct {
	RuntimeNames    []string          `json:"runtime_names,omitempty"`
	RuntimeVersions map[string]string `json:"runtime_versions,omitempty"`
}

type labelEntry struct {
	ID          string     `json:"id"`
	Label       diffLabel  `json:"label"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	Signature   string     `json:"signature,omitempty"`
	Scope       labelScope `json:"scope,omitempty"`
	Note        string     `json:"note,omitempty"`
}

type labelFile struct {
	FormatVersion int          `json:"format_version"`
	Labels        []labelEntry `json:"labels"`
}

type reportDifference struct {
	Fingerprint string `json:"fingerprint"`
	Signature   string `json:"signature"`
}

type reportSample struct {
	RuntimeVersion string `json:"runtime_version"`
}

type mismatchReport struct {
	Runtimes          []string                  `json:"runtimes"`
	ReproSamples      map[string][]reportSample `json:"repro_samples"`
	StableDifferences []reportDifference        `json:"stable_differences"`
}

var (
	flagLabels = flag.String("labels", "", "label JSON file to create or update")
	flagReport = flag.String("report", "", "stored mismatch report.json")
	flagIndex  = flag.Int("index", 0, "stable_differences index to label")
	flagID     = flag.String("id", "", "stable human-readable label ID")
	flagLabel  = flag.String("label", "", "classification (expected_version_difference, environment_difference, infrastructure_or_incomplete, kernel_bug_candidate, unknown)")
	flagMatch  = flag.String("match", "signature", "match key: signature, fingerprint, or both")
	flagNote   = flag.String("note", "", "review note")
	flagList   = flag.Bool("list", false, "list labels instead of adding one")
)

func main() {
	flag.Parse()
	if *flagLabels == "" {
		log.Fatal("-labels is required")
	}
	labels, err := readLabels(*flagLabels)
	if err != nil {
		log.Fatal(err)
	}
	if *flagList {
		if *flagReport == "" {
			printLabels(labels)
		} else {
			report, err := readReport(*flagReport)
			if err != nil {
				log.Fatal(err)
			}
			printReportLabels(labels, report)
		}
		return
	}
	if *flagReport == "" || *flagID == "" || *flagLabel == "" {
		log.Fatal("-report, -id, and -label are required (or use -list)")
	}
	if !validLabels[diffLabel(*flagLabel)] {
		log.Fatalf("unsupported label %q", *flagLabel)
	}
	if *flagMatch != "signature" && *flagMatch != "fingerprint" && *flagMatch != "both" {
		log.Fatalf("unsupported -match %q", *flagMatch)
	}
	report, err := readReport(*flagReport)
	if err != nil {
		log.Fatal(err)
	}
	if *flagIndex < 0 || *flagIndex >= len(report.StableDifferences) {
		log.Fatalf("difference index %d is outside stable_differences (length %d)",
			*flagIndex, len(report.StableDifferences))
	}
	for _, entry := range labels.Labels {
		if entry.ID == *flagID {
			log.Fatalf("label ID %q already exists", *flagID)
		}
	}
	difference := report.StableDifferences[*flagIndex]
	entry := labelEntry{ID: *flagID, Label: diffLabel(*flagLabel), Note: *flagNote,
		Scope: reportScope(report)}
	switch *flagMatch {
	case "signature":
		entry.Signature = difference.Signature
	case "fingerprint":
		entry.Fingerprint = difference.Fingerprint
	case "both":
		entry.Signature = difference.Signature
		entry.Fingerprint = difference.Fingerprint
	}
	if entry.Signature == "" && entry.Fingerprint == "" {
		log.Fatalf("stable_differences[%d] has no fingerprint or signature", *flagIndex)
	}
	labels.FormatVersion = 1
	labels.Labels = append(labels.Labels, entry)
	if err := writeLabels(*flagLabels, labels); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("added label %q for stable_differences[%d]\n", entry.ID, *flagIndex)
}

func readLabels(path string) (labelFile, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return labelFile{FormatVersion: 1}, nil
	}
	if err != nil {
		return labelFile{}, err
	}
	var labels labelFile
	if err := json.Unmarshal(data, &labels); err != nil {
		return labelFile{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if labels.FormatVersion != 0 && labels.FormatVersion != 1 {
		return labelFile{}, fmt.Errorf("unsupported format_version %d", labels.FormatVersion)
	}
	seen := make(map[string]bool)
	for _, entry := range labels.Labels {
		if entry.ID == "" || seen[entry.ID] {
			return labelFile{}, fmt.Errorf("duplicate or empty label ID %q", entry.ID)
		}
		if !validLabels[entry.Label] {
			return labelFile{}, fmt.Errorf("unsupported label %q", entry.Label)
		}
		if entry.Fingerprint == "" && entry.Signature == "" {
			return labelFile{}, fmt.Errorf("label %q has no fingerprint or signature", entry.ID)
		}
		seen[entry.ID] = true
	}
	return labels, nil
}

func readReport(path string) (mismatchReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mismatchReport{}, err
	}
	var report mismatchReport
	if err := json.Unmarshal(data, &report); err != nil {
		return mismatchReport{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return report, nil
}

func reportScope(report mismatchReport) labelScope {
	names := append([]string(nil), report.Runtimes...)
	if len(names) == 0 {
		for name := range report.ReproSamples {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	versions := make(map[string]string)
	for _, name := range names {
		if samples := report.ReproSamples[name]; len(samples) != 0 {
			if version := strings.TrimSpace(samples[0].RuntimeVersion); version != "" {
				versions[name] = version
			}
		}
	}
	if len(versions) == 0 {
		versions = nil
	}
	return labelScope{RuntimeNames: names, RuntimeVersions: versions}
}

func writeLabels(path string, labels labelFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".runtime-diff-labels-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(labels); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func printLabels(labels labelFile) {
	for _, entry := range labels.Labels {
		match := entry.Signature
		if match == "" {
			match = entry.Fingerprint
		}
		fmt.Printf("%s\t%s\t%s\n", entry.ID, entry.Label, match)
	}
}

func printReportLabels(labels labelFile, report mismatchReport) {
	scope := reportScope(report)
	for index, difference := range report.StableDifferences {
		matched := []string{}
		for _, entry := range labels.Labels {
			if entry.Fingerprint != "" && entry.Fingerprint != difference.Fingerprint {
				continue
			}
			if entry.Signature != "" && entry.Signature != difference.Signature {
				continue
			}
			if !scopeMatches(entry.Scope, scope) {
				continue
			}
			matched = append(matched, entry.ID+"="+string(entry.Label))
		}
		fmt.Printf("%d\t%s\t%s\t%s\n", index, difference.Signature,
			difference.Fingerprint, strings.Join(matched, ","))
	}
}

func scopeMatches(want, got labelScope) bool {
	if len(want.RuntimeNames) != 0 && !stringSlicesEqual(want.RuntimeNames, got.RuntimeNames) {
		return false
	}
	for name, version := range want.RuntimeVersions {
		if got.RuntimeVersions[name] != version {
			return false
		}
	}
	return true
}

func stringSlicesEqual(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
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
