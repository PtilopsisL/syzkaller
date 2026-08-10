// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
)

const MaxOutputCaptureBytesPerCall = 16 << 10

// OutputCapture describes a post-call memory range that contains output arguments.
type OutputCapture struct {
	ID           uint32
	Addr         uint64
	Size         uint64
	OriginalSize uint64
	Truncated    bool
	Path         string
	Arg          Arg
	OutputPolicy OutputPolicy
	PolicyScope  string
}

// OutputCapturePlan returns the deterministic post-call capture plan for a call.
func (p *Prog) OutputCapturePlan(callIndex int) []OutputCapture {
	if callIndex < 0 || callIndex >= len(p.Calls) {
		return nil
	}
	return outputCapturePlan(p.Target, p.Calls[callIndex])
}

func outputCapturePlan(target *Target, call *Call) []OutputCapture {
	var captures []OutputCapture
	var used uint64
	var walk func(Arg, string, OutputPolicy, string, OutputPolicy)
	walk = func(arg Arg, path string, inherited OutputPolicy, inheritedScope string,
		fieldPolicy OutputPolicy) {
		policy := inherited
		scope := inheritedScope
		if typePolicy := TypeOutputPolicy(arg.Type()); !typePolicy.Empty() {
			policy = MergeOutputPolicy(policy, typePolicy)
			scope = outputPolicyScope(path, typePolicy.Scope)
		}
		if !fieldPolicy.Empty() {
			policy = MergeOutputPolicy(policy, fieldPolicy)
			scope = outputPolicyScope(path, fieldPolicy.Scope)
		}
		switch a := arg.(type) {
		case *PointerArg:
			if a.Res == nil {
				return
			}
			if hasDirectOutputArg(a.Res) && used < MaxOutputCaptureBytesPerCall {
				originalSize := a.Res.Size()
				size := min(originalSize, uint64(MaxOutputCaptureBytesPerCall)-used)
				if size != 0 {
					captures = append(captures, OutputCapture{
						ID:           uint32(len(captures)),
						Addr:         target.PhysicalAddr(a),
						Size:         size,
						OriginalSize: originalSize,
						Truncated:    size != originalSize,
						Path:         path,
						Arg:          a.Res,
						OutputPolicy: policy,
						PolicyScope:  scope,
					})
					used += size
				}
			}
			walk(a.Res, path, policy, scope, OutputPolicy{})
		case *GroupArg:
			switch typ := a.Type().(type) {
			case *StructType:
				for i, inner := range a.Inner {
					name := fmt.Sprintf("%d", i)
					var childPolicy OutputPolicy
					if i < len(typ.Fields) {
						childPolicy = typ.Fields[i].OutputPolicy
						if typ.Fields[i].Name != "" {
							name = typ.Fields[i].Name
						}
					}
					walk(inner, path+"."+name, policy, scope, childPolicy)
				}
			case *ArrayType:
				for i, inner := range a.Inner {
					walk(inner, fmt.Sprintf("%s[%d]", path, i), policy, scope, OutputPolicy{})
				}
			}
		case *UnionArg:
			name := "option"
			var childPolicy OutputPolicy
			if typ, ok := a.Type().(*UnionType); ok && a.Index >= 0 && a.Index < len(typ.Fields) {
				name = typ.Fields[a.Index].Name
				childPolicy = typ.Fields[a.Index].OutputPolicy
			}
			walk(a.Option, path+"."+name, policy, scope, childPolicy)
		}
	}
	for i, arg := range call.Args {
		var fieldPolicy OutputPolicy
		if i < len(call.Meta.Args) {
			fieldPolicy = call.Meta.Args[i].OutputPolicy
		}
		walk(arg, fmt.Sprintf("arg[%d]", i), OutputPolicy{}, "", fieldPolicy)
	}
	return captures
}

func outputPolicyScope(path, declared string) string {
	if declared == "" {
		return path
	}
	if index := strings.LastIndexByte(path, '.'); index != -1 {
		return path[:index] + "#" + declared
	}
	return path + "#" + declared
}

func hasDirectOutputArg(arg Arg) bool {
	if IsPad(arg.Type()) {
		return false
	}
	switch a := arg.(type) {
	case *PointerArg:
		return a.Dir() != DirIn
	case *GroupArg:
		for _, inner := range a.Inner {
			if hasDirectOutputArg(inner) {
				return true
			}
		}
	case *UnionArg:
		return hasDirectOutputArg(a.Option)
	default:
		return a.Dir() != DirIn
	}
	return false
}
