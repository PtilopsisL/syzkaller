// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

// This file contains the discovery and history analysis used by the
// multi-runtime mismatch mode of syz-bisect.  The manager deliberately keeps
// the report format private (syz-manager is a command package), so the
// bisection tool has a small, forward-compatible reader for the fields it
// needs here.

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vcs"
)

const mismatchCauseFile = "cause.commit"

type storedMismatchForBisect struct {
	FormatVersion     int                         `json:"format_version"`
	ParentProgID      int64                       `json:"parent_prog_id"`
	ReproProgID       int64                       `json:"repro_prog_id"`
	Outcome           string                      `json:"outcome"`
	Runtimes          []string                    `json:"runtimes"`
	ReproSamples      map[string][]mismatchSample `json:"repro_samples"`
	StableDifferences []storedMismatchDifference  `json:"stable_differences"`
}

type mismatchSample struct {
	RuntimeVersion string `json:"runtime_version,omitempty"`
}

type storedMismatchDifference struct {
	Kind      string                     `json:"kind"`
	Path      string                     `json:"path"`
	Values    map[string]json.RawMessage `json:"values"`
	CallIndex *int                       `json:"call_index,omitempty"`
	CallName  string                     `json:"call_name,omitempty"`
	Signature string                     `json:"signature,omitempty"`
}

type mismatchCandidate struct {
	ProgID    int64
	Dir       string
	ReproPath string
	Report    storedMismatchForBisect

	// History is populated by analyzeMismatchHistory. Keeping discovery and
	// git access separate makes scanning deterministic and easy to test.
	History mismatchHistory
}

type mismatchHistory struct {
	Points  []mismatchRuntimePoint
	Pattern string
	Good    *mismatchRuntimePoint
	Bad     *mismatchRuntimePoint
}

type mismatchRuntimePoint struct {
	Name    string
	Version string
	Commit  *vcs.Commit
	Key     string
}

var (
	errMismatchIncomplete   = errors.New("incomplete minimized mismatch")
	errMismatchNotCandidate = errors.New("report is not a stable runtime mismatch")
)

// loadSingleMismatchCandidate accepts the three paths that are useful while
// debugging a report by hand:
//
//   - <workdir>/runtime-mismatches/progN (the program directory),
//   - <...>/progN/minimize (the minimized directory), or
//   - <...>/progN/minimize/report.json (the report itself).
//
// The program directory is retained in the candidate so cause.commit is
// written next to the report, regardless of which of the three forms the
// caller used.
func loadSingleMismatchCandidate(path string) (*mismatchCandidate, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("mismatch report path is empty")
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat mismatch report path %q: %w", path, err)
	}
	var root, minimizeDir string
	if info.IsDir() {
		base := filepath.Base(path)
		switch {
		case base == "minimize":
			root, minimizeDir = filepath.Dir(path), path
		case strings.HasPrefix(base, "prog") && filepath.Base(filepath.Dir(path)) == "runtime-mismatches":
			root, minimizeDir = path, filepath.Join(path, "minimize")
		case fileExists(filepath.Join(path, "report.json")) || fileExists(filepath.Join(path, "repro.prog")):
			// This also makes a standalone report directory usable when it is
			// copied out of the manager workdir for debugging.
			root, minimizeDir = path, path
		case fileExists(filepath.Join(path, "minimize", "report.json")) ||
			fileExists(filepath.Join(path, "minimize", "repro.prog")):
			root, minimizeDir = path, filepath.Join(path, "minimize")
		default:
			return nil, fmt.Errorf("directory %q does not contain report.json/repro.prog or a minimize subdirectory", path)
		}
	} else {
		if filepath.Base(path) != "report.json" {
			return nil, fmt.Errorf("mismatch report path %q is not report.json or a report directory", path)
		}
		minimizeDir = filepath.Dir(path)
		if filepath.Base(minimizeDir) == "minimize" {
			root = filepath.Dir(minimizeDir)
		} else {
			root = minimizeDir
		}
	}
	return loadMismatchCandidateAt(root, minimizeDir)
}

type mismatchCandidateSelection struct {
	Candidates []*mismatchCandidate
	Failures   []error
	Skipped    int
	Batch      bool
}

// loadMismatchCandidates distinguishes the explicitly named batch directory
// from all of the single-report path forms accepted by
// loadSingleMismatchCandidate. Requiring the directory to be named
// runtime-mismatches prevents a broad path such as the manager workdir from
// accidentally starting every pending bisection.
func loadMismatchCandidates(path string) (*mismatchCandidateSelection, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("mismatch report path is empty")
	}
	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("stat mismatch report path %q: %w", cleanPath, err)
	}
	if info.IsDir() && filepath.Base(cleanPath) == "runtime-mismatches" {
		selection, err := scanMismatchDirectoryBestEffort(cleanPath)
		if selection != nil {
			selection.Batch = true
		}
		return selection, err
	}
	candidate, err := loadSingleMismatchCandidate(cleanPath)
	if err != nil {
		return nil, err
	}
	return &mismatchCandidateSelection{Candidates: []*mismatchCandidate{candidate}}, nil
}

// looksLikeMismatchPath is used only for compatibility with the historical
// -crash flag. It deliberately requires a report-shaped path so an ordinary
// crash directory containing repro.prog is not routed into mismatch mode.
func looksLikeMismatchPath(path string) bool {
	if path == "" {
		return false
	}
	path = filepath.Clean(path)
	base := filepath.Base(path)
	if base == "runtime-mismatches" || base == "report.json" ||
		(base == "minimize" && strings.HasPrefix(filepath.Base(filepath.Dir(path)), "prog") &&
			filepath.Base(filepath.Dir(filepath.Dir(path))) == "runtime-mismatches") ||
		(strings.HasPrefix(base, "prog") && filepath.Base(filepath.Dir(path)) == "runtime-mismatches") {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return filepath.Base(path) == "report.json"
	}
	return fileExists(filepath.Join(path, "report.json")) ||
		fileExists(filepath.Join(path, "minimize", "report.json"))
}

func loadMismatchCandidateAt(root, minimizeDir string) (*mismatchCandidate, error) {
	if fileExists(filepath.Join(root, mismatchCauseFile)) {
		return nil, fmt.Errorf("mismatch has already been bisected (%s exists)",
			filepath.Join(root, mismatchCauseFile))
	}
	reproPath := filepath.Join(minimizeDir, "repro.prog")
	reportPath := filepath.Join(minimizeDir, "report.json")
	if !fileExists(reproPath) || !fileExists(reportPath) {
		return nil, fmt.Errorf("%w: expected %s and %s", errMismatchIncomplete,
			reproPath, reportPath)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read mismatch report %q: %w", reportPath, err)
	}
	var report storedMismatchForBisect
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode mismatch report %q: %w", reportPath, err)
	}
	if report.Outcome != "mismatch" || len(report.StableDifferences) == 0 {
		return nil, fmt.Errorf("%w: outcome=%q stable_differences=%d",
			errMismatchNotCandidate, report.Outcome, len(report.StableDifferences))
	}
	progID, ok := mismatchProgID(filepath.Base(root))
	if report.ParentProgID != 0 {
		progID, ok = report.ParentProgID, true
	} else if !ok && report.ReproProgID != 0 {
		progID, ok = report.ReproProgID, true
	}
	if !ok {
		return nil, fmt.Errorf("cannot determine program ID from %q or mismatch report", root)
	}
	return &mismatchCandidate{
		ProgID: progID, Dir: root, ReproPath: reproPath, Report: report,
	}, nil
}

// scanMinimizedMismatches returns one candidate for every complete minimized
// report. A marker file is intentionally checked before reading the report:
// once a cause.commit exists the program has already been bisected, even if a
// previous invocation was interrupted while printing its result.
func scanMinimizedMismatches(workdir string) ([]*mismatchCandidate, error) {
	return scanMismatchDirectory(filepath.Join(workdir, "runtime-mismatches"))
}

func scanMismatchDirectory(base string) ([]*mismatchCandidate, error) {
	selection, err := scanMismatchDirectoryBestEffort(base)
	if err != nil {
		return nil, err
	}
	if len(selection.Failures) != 0 {
		return nil, errors.Join(selection.Failures...)
	}
	return selection.Candidates, nil
}

func scanMismatchDirectoryBestEffort(base string) (*mismatchCandidateSelection, error) {
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &mismatchCandidateSelection{}, nil
		}
		return nil, fmt.Errorf("read mismatch directory %q: %w", base, err)
	}
	selection := new(mismatchCandidateSelection)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "prog") {
			continue
		}
		id, ok := mismatchProgID(entry.Name())
		if !ok {
			continue
		}
		dir := filepath.Join(base, entry.Name())
		if fileExists(filepath.Join(dir, mismatchCauseFile)) {
			selection.Skipped++
			continue
		}
		minimizeDir := filepath.Join(dir, "minimize")
		candidate, err := loadMismatchCandidateAt(dir, minimizeDir)
		if err != nil {
			// Reports are written atomically but the reproducer and report are
			// separate files. Ignore an incomplete/non-mismatch directory and
			// let the next invocation pick it up.
			if errors.Is(err, errMismatchIncomplete) || errors.Is(err, errMismatchNotCandidate) {
				selection.Skipped++
				continue
			}
			selection.Failures = append(selection.Failures, fmt.Errorf("prog %d: %w", id, err))
			continue
		}
		if candidate.ProgID != id && candidate.Report.ParentProgID == 0 {
			// The directory name is the authoritative identity for a report
			// without an explicit parent ID.
			candidate.ProgID = id
		}
		selection.Candidates = append(selection.Candidates, candidate)
	}
	slices.SortFunc(selection.Candidates, func(a, b *mismatchCandidate) int {
		return cmp.Compare(a.ProgID, b.ProgID)
	})
	return selection, nil
}

func mismatchProgID(name string) (int64, bool) {
	if !strings.HasPrefix(name, "prog") {
		return 0, false
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(name, "prog"), 10, 64)
	return id, err == nil && id >= 0
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// mismatchBehaviorKey projects all stable fields onto one runtime. The
// resulting digest is intentionally independent of map iteration order and of
// the order in which the manager happened to emit differences.
func mismatchBehaviorKey(report *storedMismatchForBisect, runtime string) (string, error) {
	if report == nil || len(report.StableDifferences) == 0 {
		return "", fmt.Errorf("report has no stable differences")
	}
	type field struct {
		Kind      string          `json:"kind"`
		Path      string          `json:"path"`
		Signature string          `json:"signature,omitempty"`
		Value     json.RawMessage `json:"value"`
	}
	fields := make([]field, 0, len(report.StableDifferences))
	for _, difference := range report.StableDifferences {
		value, ok := difference.Values[runtime]
		if !ok {
			return "", fmt.Errorf("stable difference %q has no value for runtime %q",
				difference.Path, runtime)
		}
		value, err := canonicalJSON(value)
		if err != nil {
			return "", fmt.Errorf("canonicalize %s for runtime %q: %w",
				difference.Path, runtime, err)
		}
		fields = append(fields, field{
			Kind: difference.Kind, Path: difference.Path, Signature: difference.Signature,
			Value: value,
		})
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].Kind != fields[j].Kind {
			return fields[i].Kind < fields[j].Kind
		}
		if fields[i].Path != fields[j].Path {
			return fields[i].Path < fields[j].Path
		}
		return fields[i].Signature < fields[j].Signature
	})
	data, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalJSON(data json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("empty JSON value")
	}
	// Decode accepts a stream of values, whereas a stable field must contain
	// exactly one JSON value. Keep the validation previously provided by Unmarshal.
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid JSON value")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	// Syscall results can use all 64 bits. Converting them to float64 would
	// merge distinct integers above 2^53 before we compute the behavior digest.
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

// classifyMismatchHistory verifies the shape required for a useful commit
// bisection when the caller has already selected runtime order. The production
// path uses classifyMismatchPoints after ordering commits by ancestry.
func classifyMismatchHistory(report *storedMismatchForBisect) (mismatchHistory, error) {
	if report == nil {
		return mismatchHistory{}, fmt.Errorf("nil report")
	}
	names := mismatchRuntimeNames(report)
	var points []mismatchRuntimePoint
	for _, name := range names {
		key, err := mismatchBehaviorKey(report, name)
		if err != nil {
			return mismatchHistory{}, err
		}
		points = append(points, mismatchRuntimePoint{Name: name, Key: key})
	}
	return classifyMismatchPoints(points)
}

func mismatchRuntimeNames(report *storedMismatchForBisect) []string {
	names := slices.Clone(report.Runtimes)
	if len(names) == 0 {
		for name := range report.ReproSamples {
			names = append(names, name)
		}
		slices.Sort(names)
	}
	seen := make(map[string]bool, len(names))
	ret := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		ret = append(ret, name)
	}
	return ret
}

func classifyMismatchPoints(points []mismatchRuntimePoint) (mismatchHistory, error) {
	if len(points) < 2 {
		return mismatchHistory{}, fmt.Errorf("only %d runtime with stable values", len(points))
	}
	// Use the first observed class as A and the second as B. More than one
	// transition means the runtime behavior is not a monotonic commit history.
	classA := points[0].Key
	classB := ""
	transition := -1
	for i := range points {
		if points[i].Key == classA {
			if transition >= 0 {
				return mismatchHistory{}, fmt.Errorf("runtime behavior returns to A at %s", points[i].Name)
			}
			continue
		}
		if classB == "" {
			classB = points[i].Key
			transition = i
			continue
		}
		if points[i].Key != classB {
			return mismatchHistory{}, fmt.Errorf("more than two runtime behavior classes")
		}
	}
	if transition <= 0 || classB == "" || transition == len(points) {
		return mismatchHistory{}, fmt.Errorf("runtime behavior is not A+ B+")
	}
	var pattern strings.Builder
	for _, point := range points {
		if point.Key == classA {
			pattern.WriteByte('A')
		} else {
			pattern.WriteByte('B')
		}
	}
	history := mismatchHistory{Points: points, Pattern: pattern.String()}
	history.Good = &history.Points[transition-1]
	// The last B is the current bad endpoint. Bisection can then find the
	// earliest bad commit between the last known-good and current revision.
	history.Bad = &history.Points[len(history.Points)-1]
	return history, nil
}

// analyzeMismatchHistory resolves runtime versions to commits and orders all
// observations along one ancestry chain. Reported runtime_version takes
// precedence over the current config's KernelVersion and release-like names.
func analyzeMismatchHistory(candidate *mismatchCandidate, cfg *mgrconfig.Config) error {
	if candidate == nil || cfg == nil {
		return fmt.Errorf("candidate/config is nil")
	}
	names := mismatchRuntimeNames(&candidate.Report)
	if len(names) < 2 {
		return fmt.Errorf("only %d runtime with stable values", len(names))
	}
	points := make([]mismatchRuntimePoint, 0, len(names))
	for _, name := range names {
		key, err := mismatchBehaviorKey(&candidate.Report, name)
		if err != nil {
			return err
		}
		points = append(points, mismatchRuntimePoint{Name: name, Key: key})
	}
	var repos []vcs.Repo
	for i := range points {
		point := &points[i]
		version := runtimeVersion(candidate.Report.ReproSamples, point.Name)
		if version == "" {
			if runtimeCfg := configForRuntime(cfg, point.Name); runtimeCfg != nil {
				version = runtimeCfg.KernelVersion
			}
		}
		if version == "" {
			// Older reports used release-like runtime names as the version
			// identity. Keep that fallback for names such as v6.8 while still
			// producing a useful resolution error for arbitrary names.
			version = point.Name
		}
		version = strings.TrimSpace(version)
		runtimeCfg := configForRuntime(cfg, point.Name)
		if runtimeCfg == nil {
			return fmt.Errorf("runtime %q is not present in manager config", point.Name)
		}
		source := runtimeCfg.KernelSrc
		if source == "" {
			source = runtimeCfg.KernelObj
		}
		if source == "" {
			return fmt.Errorf("runtime %q has no kernel source", point.Name)
		}
		repo, err := vcs.NewRepo(runtimeCfg.TargetOS, runtimeCfg.Type, source, vcs.OptPrecious)
		if err != nil {
			return fmt.Errorf("open kernel repo for runtime %q: %w", point.Name, err)
		}
		commit, err := resolveRuntimeCommit(repo, version)
		if err != nil {
			return fmt.Errorf("resolve runtime %q version %q: %w", point.Name, version, err)
		}
		point.Version, point.Commit = version, commit
		repos = append(repos, repo)
	}
	points, err := orderMismatchPoints(points, repos)
	if err != nil {
		return err
	}
	history, err := classifyMismatchPoints(points)
	if err != nil {
		return err
	}
	candidate.History = history
	return nil
}

func orderMismatchPoints(points []mismatchRuntimePoint, repos []vcs.Repo) ([]mismatchRuntimePoint, error) {
	// A comparison_primary snapshot can intentionally point at the same kernel
	// commit as the primary slot. Coalesce such duplicate observations when
	// their behavior agrees; conflicting behavior at one commit cannot be
	// attributed to a commit and is rejected.
	var unique []mismatchRuntimePoint
	seen := make(map[string]mismatchRuntimePoint)
	for _, point := range points {
		if prev, ok := seen[point.Commit.Hash]; ok {
			if prev.Key != point.Key {
				return nil, fmt.Errorf("runtimes %q and %q disagree at commit %s",
					prev.Name, point.Name, point.Commit.Hash)
			}
			continue
		}
		seen[point.Commit.Hash] = point
		unique = append(unique, point)
	}
	if len(unique) < 2 {
		return unique, nil
	}
	// Runtime sources may be separate clones. The descendant's full repository
	// must contain every observed ancestor. Find it without fetching or changing
	// any runtime checkout, and without assuming which runtime is newest.
	repo, err := mismatchHistoryRepo(unique, repos)
	if err != nil {
		return nil, err
	}
	var ordered []mismatchRuntimePoint
	for _, point := range unique {
		index := len(ordered)
		for i, prev := range ordered {
			bases, err := repo.MergeBases(prev.Commit.Hash, point.Commit.Hash)
			if err != nil {
				return nil, fmt.Errorf("find ancestry between runtimes %q (%s) and %q (%s): %w",
					prev.Name, prev.Commit.Hash, point.Name, point.Commit.Hash, err)
			}
			if len(bases) != 1 || (bases[0].Hash != prev.Commit.Hash && bases[0].Hash != point.Commit.Hash) {
				return nil, fmt.Errorf("runtimes %q (%s) and %q (%s) are not on one ancestry chain",
					prev.Name, prev.Commit.Hash, point.Name, point.Commit.Hash)
			}
			if bases[0].Hash == point.Commit.Hash {
				index = i
				break
			}
		}
		ordered = slices.Insert(ordered, index, point)
	}
	return ordered, nil
}

func mismatchHistoryRepo(points []mismatchRuntimePoint, repos []vcs.Repo) (vcs.Repo, error) {
	for _, repo := range repos {
		containsAll := true
		for _, point := range points {
			present, err := repo.CommitExists(point.Commit.Hash)
			if err != nil {
				return nil, fmt.Errorf("check runtime %q commit %s: %w", point.Name, point.Commit.Hash, err)
			}
			if !present {
				containsAll = false
				break
			}
		}
		if containsAll {
			return repo, nil
		}
	}
	return nil, fmt.Errorf("no runtime repository contains all observed commits; full kernel history is required")
}

func resolveRuntimeCommit(repo vcs.Repo, version string) (*vcs.Commit, error) {
	versions := []string{version}
	if !strings.HasPrefix(version, "v") && len(version) != 0 && version[0] >= '0' && version[0] <= '9' {
		versions = append(versions, "v"+version)
	}
	// Configs commonly use a descriptive release identity such as
	// v7.2-plus-73e3f071. If the tag itself is not present, try the embedded
	// abbreviated commit as a last resort.
	parts := strings.FieldsFunc(version, func(r rune) bool { return r == '-' || r == '+' || r == '/' })
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if len(part) < 7 || len(part) > 40 {
			continue
		}
		valid := true
		for _, char := range part {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') ||
				(char >= 'A' && char <= 'F')) {
				valid = false
				break
			}
		}
		if valid {
			versions = append(versions, part)
			break
		}
	}
	var err error
	for _, candidate := range versions {
		commit, resolveErr := repo.Commit(candidate)
		if resolveErr == nil {
			return commit, nil
		}
		err = resolveErr
	}
	return nil, err
}

func runtimeVersion(samples map[string][]mismatchSample, runtime string) string {
	for _, sample := range samples[runtime] {
		if sample.RuntimeVersion != "" {
			return sample.RuntimeVersion
		}
	}
	return ""
}

// configForRuntime handles the synthetic primary-fuzzing slot used when a
// comparison_primary snapshot is configured. Reports use the execution slot
// name, whereas RuntimeConfigs is keyed by the user-facing runtime name.
func configForRuntime(cfg *mgrconfig.Config, runtime string) *mgrconfig.Config {
	if cfg == nil {
		return nil
	}
	if runtimeCfg := cfg.RuntimeConfigs[runtime]; runtimeCfg != nil {
		return runtimeCfg
	}
	if runtime == cfg.PrimaryRuntime || runtime == cfg.PrimaryFuzzingRuntimeName() {
		if runtimeCfg := cfg.RuntimeConfigs[cfg.PrimaryRuntime]; runtimeCfg != nil {
			return runtimeCfg
		}
		return cfg
	}
	return nil
}
