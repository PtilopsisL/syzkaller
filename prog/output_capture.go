// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import "fmt"

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
	var walk func(Arg, string)
	walk = func(arg Arg, path string) {
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
					})
					used += size
				}
			}
			walk(a.Res, path)
		case *GroupArg:
			switch typ := a.Type().(type) {
			case *StructType:
				for i, inner := range a.Inner {
					name := fmt.Sprintf("%d", i)
					if i < len(typ.Fields) && typ.Fields[i].Name != "" {
						name = typ.Fields[i].Name
					}
					walk(inner, path+"."+name)
				}
			case *ArrayType:
				for i, inner := range a.Inner {
					walk(inner, fmt.Sprintf("%s[%d]", path, i))
				}
			}
		case *UnionArg:
			name := "option"
			if typ, ok := a.Type().(*UnionType); ok && a.Index >= 0 && a.Index < len(typ.Fields) {
				name = typ.Fields[a.Index].Name
			}
			walk(a.Option, path+"."+name)
		}
	}
	for i, arg := range call.Args {
		walk(arg, fmt.Sprintf("arg[%d]", i))
	}
	return captures
}

func hasDirectOutputArg(arg Arg) bool {
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
