// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import "fmt"

// OutputPolicyKind describes how a syscall output participates in runtime
// result comparison. An empty kind is deliberately distinct from Semantic:
// it means that no policy was declared and a containing type may provide one.
type OutputPolicyKind string

const (
	OutputPolicySemantic           OutputPolicyKind = "semantic"
	OutputPolicyResourceIdentity   OutputPolicyKind = "resource_identity"
	OutputPolicyObjectIdentity     OutputPolicyKind = "object_identity"
	OutputPolicyAddress            OutputPolicyKind = "address"
	OutputPolicyTimestamp          OutputPolicyKind = "timestamp"
	OutputPolicyFilesystemIdentity OutputPolicyKind = "filesystem_identity"
	OutputPolicyCounter            OutputPolicyKind = "counter"
	OutputPolicyReserved           OutputPolicyKind = "reserved"
	OutputPolicyVersionIdentity    OutputPolicyKind = "version_identity"
)

var validOutputPolicyKinds = map[OutputPolicyKind]bool{
	OutputPolicySemantic:           true,
	OutputPolicyResourceIdentity:   true,
	OutputPolicyObjectIdentity:     true,
	OutputPolicyAddress:            true,
	OutputPolicyTimestamp:          true,
	OutputPolicyFilesystemIdentity: true,
	OutputPolicyCounter:            true,
	OutputPolicyReserved:           true,
	OutputPolicyVersionIdentity:    true,
}

// OutputPolicy is comparison metadata, not an executor instruction. Domain
// separates independent identity namespaces and Mode selects a generic handler
// mode.
type OutputPolicy struct {
	Kind   OutputPolicyKind `json:"kind,omitempty"`
	Domain string           `json:"domain,omitempty"`
	Mode   string           `json:"mode,omitempty"`
}

func ParseOutputPolicyKind(value string) (OutputPolicyKind, error) {
	kind := OutputPolicyKind(value)
	if !validOutputPolicyKinds[kind] {
		return "", fmt.Errorf("unknown output policy %q", value)
	}
	return kind, nil
}

// ValidateOutputPolicy rejects modes that a canonicalizer would otherwise
// silently interpret as its default behavior.
func ValidateOutputPolicy(policy OutputPolicy) error {
	if policy.Kind != "" && !validOutputPolicyKinds[policy.Kind] {
		return fmt.Errorf("unknown output policy %q", policy.Kind)
	}
	if policy.Mode == "" || policy.Kind == "" {
		return nil
	}
	valid := false
	switch policy.Kind {
	case OutputPolicyAddress:
		valid = policy.Mode == "identity" || policy.Mode == "strict_identity"
	case OutputPolicyTimestamp, OutputPolicyCounter:
		valid = policy.Mode == "exact"
	}
	if !valid {
		return fmt.Errorf("unsupported output mode %q for policy %q",
			policy.Mode, policy.Kind)
	}
	return nil
}

func (policy OutputPolicy) EffectiveKind() OutputPolicyKind {
	if policy.Kind == "" {
		return OutputPolicySemantic
	}
	return policy.Kind
}

func (policy OutputPolicy) Empty() bool {
	return policy.Kind == "" && policy.Domain == "" && policy.Mode == ""
}

// MergeOutputPolicy applies a more specific declaration without discarding
// inherited parameters that it did not override.
func MergeOutputPolicy(base, override OutputPolicy) OutputPolicy {
	if override.Kind != "" {
		base.Kind = override.Kind
	}
	if override.Domain != "" {
		base.Domain = override.Domain
	}
	if override.Mode != "" {
		base.Mode = override.Mode
	}
	return base
}

// TypeOutputPolicy returns comparison metadata declared on a composite type.
// Primitive field-specific semantics live on Field.OutputPolicy.
func TypeOutputPolicy(typ Type) OutputPolicy {
	switch typ := typ.(type) {
	case *StructType:
		return typ.OutputPolicy
	case *UnionType:
		return typ.OutputPolicy
	default:
		return OutputPolicy{}
	}
}
