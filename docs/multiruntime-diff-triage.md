# Multi-runtime diff triage

Multi-runtime comparison keeps every stable difference. It does not infer that
an older/newer kernel difference is a bug and it does not discard a report
because a label matches.

## Snapshot-isolated comparison primary

Use `comparison_primary` to keep normal primary fuzzing outside snapshot mode
while comparing every identified generated program in clean snapshot runtimes:

```json
{
  "snapshot": true,
  "primary": "linux-new",
  "comparison_primary": "linux-new-comparison",
  "runtimes": [
    {"name": "linux-new"},
    {"name": "linux-old"}
  ]
}
```

The manager automatically clones the `linux-new` runtime configuration as
`linux-new-comparison`; do not add that name to `runtimes`. The normal
primary runs in the `linux-new-fuzzing` execution slot with snapshot disabled
and remains responsible for coverage and fuzzing. The clone and all shadow
runtimes retain snapshot mode, receive only programs with a generated program
ID, and provide the initial and reproduction samples used by the differential
comparison. Results from the normal primary are still recorded under its
fuzzing slot name, but are excluded from both comparisons and mismatch
reproduction.

Execution slot names remain distinct for queues, RPC, statistics, and crash
namespaces. At the comparison boundary, `linux-new-comparison` is mapped back
to the logical runtime name `linux-new`. Consequently, `report.json`, trace
file names, stable-difference value maps, fingerprints, and diff-label scopes
continue to use `linux-new`, preserving compatibility with reports and labels
from the original primary.

`comparison_primary` requires `snapshot: true`, must differ from `primary`, and
must not collide with another configured runtime name. The derived
`<primary>-fuzzing` slot name must also be unique. The normal primary keeps the
manager workdir root, while the snapshot clone uses
`<workdir>/runtimes/<comparison_primary>`. Local crash namespaces and runtime
statistics use the physical slot names.

Set `runtime_diff_labels` in the manager configuration to load reviewed labels:

```json
{
  "runtime_diff_labels": "runtime-diff-labels.json"
}
```

A relative path is resolved below the manager workdir. If the file is absent,
comparison continues with no labels. A malformed file stops manager startup so
a review database cannot be silently ignored.

Each stable difference in `report.json` contains:

- `signature`: a semantic hash of the difference kind/path, call name, and the
  summarized syscall arguments. It omits runtime names, kernel versions, and
  observed return/output values, so it can be reviewed again on a new pair.
- `fingerprint`: a stricter hash that also includes the runtime-to-observed-value
  vector. Use it when a label must apply only to one exact observation.
- `triage_label`, `triage_label_id`, and `triage_note` when a reviewed label
  matched.

The report-level `triage` object records the first difference's hashes and the
counts of labels. All differences remain in `stable_differences`.

To create a label from a report, build or run `syz-difftriage`:

```sh
go run ./tools/syz-difftriage \
  -labels=/path/to/workdir/runtime-diff-labels.json \
  -report=/path/to/report.json \
  -index=0 -id=rseq-abi-review \
  -label=expected_version_difference \
  -note='reviewed as an extensible rseq ABI difference'
```

The command defaults to the semantic signature and scopes the label to the
runtime names and versions recorded in that report. Use `-match=fingerprint`
for a narrower exact-observation label, or `-match=both` to require both keys.
To query existing annotations for every difference in a report, add `-list`:

```sh
go run ./tools/syz-difftriage \
  -labels=/path/to/workdir/runtime-diff-labels.json \
  -report=/path/to/report.json -list
```
The supported labels are:

- `expected_version_difference`
- `environment_difference`
- `infrastructure_or_incomplete`
- `kernel_bug_candidate`
- `unknown`

Labels are annotations only. A future filtering policy can use labels that have
been reviewed by a human, but this implementation intentionally leaves that
decision outside the fuzzing comparison path.
