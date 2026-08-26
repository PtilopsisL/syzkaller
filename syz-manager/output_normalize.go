// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/bits"

	"github.com/google/syzkaller/prog"
)

type runtimeOutputCanonicalizer struct {
	target     *prog.Target
	identities map[string]map[uint64]int
}

func normalizeRuntimeOutputs(p *prog.Prog, result *runtimeResult) {
	if p == nil || result == nil {
		return
	}
	normalizer := &runtimeOutputCanonicalizer{
		target:     p.Target,
		identities: make(map[string]map[uint64]int),
	}
	for callIndex := range result.Calls {
		for _, capture := range result.Calls[callIndex].Outputs {
			if capture == nil {
				continue
			}
			for _, output := range capture.Values {
				if output == nil {
					continue
				}
				if err := prog.ValidateOutputPolicy(output.OutputPolicy); err != nil {
					output.NormalizationErr = err.Error()
					continue
				}
				switch output.OutputPolicy.EffectiveKind() {
				case prog.OutputPolicySemantic, prog.OutputPolicyReserved,
					prog.OutputPolicyVersionIdentity:
				// Raw values are retained or suppressed only in the comparison view.
				case prog.OutputPolicyResourceIdentity, prog.OutputPolicyObjectIdentity,
					prog.OutputPolicyFilesystemIdentity:
					normalizer.normalizeIdentity(output)
				case prog.OutputPolicyAddress:
					normalizer.normalizeAddress(output)
				case prog.OutputPolicyTimestamp:
					normalizeTimestamp(output)
				case prog.OutputPolicyCounter:
					normalizer.normalizeCounter(output)
				default:
					output.NormalizationErr = fmt.Sprintf("unsupported output policy %q",
						output.OutputPolicy.Kind)
				}
			}
		}
	}
}

func (normalizer *runtimeOutputCanonicalizer) normalizeIdentity(output *runtimeDecodedOutput) {
	if output.Value == nil {
		output.NormalizationErr = "identity output is not an integer"
		return
	}
	kind := output.OutputPolicy.EffectiveKind()
	domain := output.OutputPolicy.Domain
	if domain == "" {
		domain = output.Type
		if kind == prog.OutputPolicyFilesystemIdentity {
			domain = "mount"
		}
	}
	if output.IdentitySpecial {
		output.CanonicalValue = &runtimeCanonicalOutput{
			Kind: string(kind), Domain: domain, State: "sentinel",
			Exact: uint64Ptr(*output.Value),
		}
		return
	}
	key := string(kind) + ":" + domain
	output.CanonicalValue = &runtimeCanonicalOutput{
		Kind: string(kind), Domain: domain,
		Class: normalizer.identityClass(key, *output.Value),
	}
}

func (normalizer *runtimeOutputCanonicalizer) normalizeAddress(output *runtimeDecodedOutput) {
	if output.Value == nil {
		output.NormalizationErr = "address output is not an integer"
		return
	}
	value := *output.Value
	domain := output.OutputPolicy.Domain
	if domain == "" {
		domain = "address"
	}
	if value == 0 {
		output.CanonicalValue = &runtimeCanonicalOutput{
			Kind: string(prog.OutputPolicyAddress), Domain: domain,
			State: "null", Exact: uint64Ptr(0),
		}
		return
	}
	if normalizer.target != nil {
		base := normalizer.target.DataOffset
		size := normalizer.target.NumPages * normalizer.target.PageSize
		if value >= base && value-base < size {
			output.CanonicalValue = &runtimeCanonicalOutput{
				Kind: string(prog.OutputPolicyAddress), Domain: domain,
				Region: "program_data", Offset: uint64Ptr(value - base),
			}
			return
		}
	}
	if output.OutputPolicy.Mode != "identity" && output.OutputPolicy.Mode != "strict_identity" {
		output.NormalizationErr = "address is outside known program regions"
		return
	}
	class := "user"
	ptrBits := uint64(64)
	if normalizer.target != nil && normalizer.target.PtrSize != 0 {
		ptrBits = normalizer.target.PtrSize * 8
	}
	if value&(uint64(1)<<(ptrBits-1)) != 0 {
		class = "kernel"
	}
	canonical := &runtimeCanonicalOutput{
		Kind: string(prog.OutputPolicyAddress), Domain: domain, State: class,
		Class: normalizer.identityClass("address:"+domain+":"+class, value),
	}
	if output.OutputPolicy.Mode == "strict_identity" {
		alignmentBits := min(bits.TrailingZeros64(value), 12)
		canonical.Alignment = uint64(1) << alignmentBits
	}
	output.CanonicalValue = canonical
}

func (normalizer *runtimeOutputCanonicalizer) normalizeCounter(output *runtimeDecodedOutput) {
	if output.Value == nil {
		output.NormalizationErr = "counter output is not an integer"
		return
	}
	if output.OutputPolicy.Mode == "exact" {
		output.CanonicalValue = &runtimeCanonicalOutput{
			Kind: string(prog.OutputPolicyCounter), State: "exact",
			Exact: uint64Ptr(*output.Value),
		}
		return
	}
	state := "nonzero"
	if *output.Value == 0 {
		state = "zero"
	}
	output.CanonicalValue = &runtimeCanonicalOutput{
		Kind:   string(prog.OutputPolicyCounter),
		Domain: output.OutputPolicy.Domain,
		State:  state,
	}
}

func normalizeTimestamp(output *runtimeDecodedOutput) {
	if output.OutputPolicy.Mode != "exact" {
		return
	}
	if output.Value == nil {
		output.NormalizationErr = "timestamp output is not an integer"
		return
	}
	output.CanonicalValue = &runtimeCanonicalOutput{
		Kind: string(prog.OutputPolicyTimestamp), State: "exact",
		Exact: uint64Ptr(*output.Value),
	}
}

func (normalizer *runtimeOutputCanonicalizer) identityClass(domain string, value uint64) string {
	classes := normalizer.identities[domain]
	if classes == nil {
		classes = make(map[uint64]int)
		normalizer.identities[domain] = classes
	}
	index, ok := classes[value]
	if !ok {
		index = len(classes)
		classes[value] = index
	}
	return fmt.Sprintf("%s#%d", domain, index)
}
