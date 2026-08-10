# Runtime output policies

Multi-runtime comparison reads semantic policies from syzlang descriptions. A
manager may additionally load an overlay with `runtime_output_policy`:

```json
{
  "runtime_output_policy": "runtime-output-policy.json"
}
```

Relative paths are resolved against the manager workdir. A missing file means
that no overlay is applied. Every runtime result records the SHA-256 hash of a
loaded file.

The file format is:

```json
{
  "format_version": 1,
  "rules": [
    {
      "id": "stat-device",
      "selector": {
        "capture_type": "stat",
        "field": "st_dev"
      },
      "policy": {
        "kind": "filesystem_identity",
        "domain": "mount"
      }
    }
  ]
}
```

Selectors may use `call_name`, `capture_type`, `output_type`, `field`, and
`path`. All specified properties must match. `path` uses Go path-match
patterns; prefer type and field selectors because they are less sensitive to
argument indices.

Policy kinds are `semantic`, `resource_identity`, `object_identity`,
`address`, `timestamp`, `filesystem_identity`, `counter`, `reserved`,
and `version_identity`. `domain`, `mode`, and `scope` have the same meaning
as their syzlang counterparts.

Identity policies compare equality relationships within each domain, instead of
raw numeric IDs. Resource sentinel values remain exact. Filesystem identities
currently preserve this relationship but do not resolve device numbers back to
host mount paths.

An `address` is normalized to a region-relative offset when it is inside the
known syzkaller data region. An unknown address falls back to raw comparison.
Use `mode: "identity"` to explicitly compare unknown addresses as identity
classes, or `mode: "strict_identity"` to also retain their alignment class.
A `timestamp` compares zero/set/validity state per scope; `mode: "exact"`
keeps its numeric components. A `counter` compares zero/nonzero state unless
it also uses `mode: "exact"`.

The loader rejects unknown policy kinds and modes, empty selectors, duplicate IDs,
duplicate selectors, invalid patterns, and unsupported format versions.
If overlapping rules select conflicting kinds at runtime, canonicalization
falls back to the raw value and records a normalization error.
