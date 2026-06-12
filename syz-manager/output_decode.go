// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
)

func summarizeCallOutputs(p *prog.Prog, callIndex int,
	rawOutputs []*flatrpc.OutputCapture) []*runtimeOutputCapture {
	plan := p.OutputCapturePlan(callIndex)
	if len(plan) == 0 && len(rawOutputs) == 0 {
		return nil
	}
	rawByID := make(map[uint32]*flatrpc.OutputCapture, len(rawOutputs))
	for _, output := range rawOutputs {
		if output != nil {
			rawByID[output.Id] = output
		}
	}
	ret := make([]*runtimeOutputCapture, 0, max(len(plan), len(rawOutputs)))
	known := make(map[uint32]bool, len(plan))
	for _, capture := range plan {
		known[capture.ID] = true
		decoded := &runtimeOutputCapture{
			ID:        capture.ID,
			Path:      capture.Path,
			Type:      capture.Arg.Type().String(),
			Size:      capture.OriginalSize,
			Truncated: capture.Truncated,
		}
		raw := rawByID[capture.ID]
		if raw == nil {
			decoded.Missing = true
		} else {
			decoded.CapturedSize = uint64(len(raw.Data))
			decoded.Faulted = raw.Faulted
			decoded.Truncated = decoded.Truncated || raw.Truncated
			if !raw.Faulted {
				decoded.Values = decodeOutputArg(p.Target, capture.Arg, capture.Path, raw.Data)
			}
		}
		ret = append(ret, decoded)
	}
	for _, raw := range rawOutputs {
		if raw == nil || known[raw.Id] {
			continue
		}
		ret = append(ret, &runtimeOutputCapture{
			ID:           raw.Id,
			CapturedSize: uint64(len(raw.Data)),
			Faulted:      raw.Faulted,
			Truncated:    raw.Truncated,
		})
	}
	return ret
}

func decodeOutputArg(target *prog.Target, root prog.Arg, rootPath string,
	data []byte) []*runtimeDecodedOutput {
	var ret []*runtimeDecodedOutput
	var walk func(prog.Arg, string, uint64)
	walk = func(arg prog.Arg, path string, offset uint64) {
		switch a := arg.(type) {
		case *prog.GroupArg:
			base := offset
			overlayField := 0
			var fields []prog.Field
			if typ, ok := a.Type().(*prog.StructType); ok {
				overlayField = typ.OverlayField
				fields = typ.Fields
			}
			for i, inner := range a.Inner {
				if i == overlayField {
					offset = base
				}
				childPath := path + "[" + strconv.Itoa(i) + "]"
				if i < len(fields) && fields[i].Name != "" {
					childPath = path + "." + fields[i].Name
				}
				walk(inner, childPath, offset)
				offset += inner.Size()
			}
		case *prog.UnionArg:
			childPath := path + ".option"
			if typ, ok := a.Type().(*prog.UnionType); ok &&
				a.Index >= 0 && a.Index < len(typ.Fields) {
				childPath = path + "." + typ.Fields[a.Index].Name
			}
			walk(a.Option, childPath, offset)
		case *prog.PointerArg:
			// The pointee has its own capture and address space.
			return
		default:
			if arg.Dir() == prog.DirIn || prog.IsPad(arg.Type()) {
				return
			}
			ret = append(ret, decodeOutputValue(target, arg, path, offset, data))
		}
	}
	walk(root, rootPath, 0)
	return ret
}

func decodeOutputValue(target *prog.Target, arg prog.Arg, path string,
	offset uint64, data []byte) *runtimeDecodedOutput {
	ret := &runtimeDecodedOutput{
		Path: path,
		Type: arg.Type().String(),
		Dir:  arg.Dir().String(),
		Kind: runtimeArgKind(arg),
		Size: arg.Size(),
	}
	start := offset
	size := arg.Size()
	typ := arg.Type()
	if typ.IsBitfield() {
		if offset < typ.UnitOffset() {
			ret.Truncated = true
			return ret
		}
		start -= typ.UnitOffset()
		size = typ.UnitSize()
	}
	if _, ok := arg.(*prog.DataArg); ok {
		if start >= uint64(len(data)) {
			ret.Truncated = true
			return ret
		}
		end := start + min(size, uint64(len(data))-start)
		ret.DataSummary = summarizeOutputData(data[start:end], arg.Size())
		return ret
	}
	bytes, ok := capturedBytes(data, start, size)
	if !ok {
		ret.Truncated = true
		if start < uint64(len(data)) {
			ret.RawHex = hex.EncodeToString(data[start:])
		}
		return ret
	}
	value, ok := decodeInteger(target, typ, bytes)
	if !ok {
		ret.RawHex = hex.EncodeToString(bytes)
		return ret
	}
	if typ.IsBitfield() {
		shift := typ.BitfieldOffset()
		if target.BigEndian {
			shift = typ.UnitSize()*8 - typ.BitfieldOffset() - typ.BitfieldLength()
		}
		value = (value >> shift) & bitMask(typ.BitfieldLength())
	}
	ret.Value = uint64Ptr(value)
	ret.ValueNames = valueNames(target, typ, value)
	return ret
}

func capturedBytes(data []byte, offset, size uint64) ([]byte, bool) {
	if offset > uint64(len(data)) || size > uint64(len(data))-offset {
		return nil, false
	}
	return data[offset : offset+size], true
}

func decodeInteger(target *prog.Target, typ prog.Type, data []byte) (uint64, bool) {
	switch typ.Format() {
	case prog.FormatNative:
		return decodeBinaryInteger(data, target.BigEndian)
	case prog.FormatBigEndian:
		return decodeBinaryInteger(data, true)
	case prog.FormatStrDec:
		return decodeStringInteger(data, 10)
	case prog.FormatStrHex:
		return decodeStringInteger(data, 16)
	case prog.FormatStrOct:
		return decodeStringInteger(data, 8)
	default:
		return 0, false
	}
}

func decodeBinaryInteger(data []byte, bigEndian bool) (uint64, bool) {
	var order binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	switch len(data) {
	case 1:
		return uint64(data[0]), true
	case 2:
		return uint64(order.Uint16(data)), true
	case 4:
		return uint64(order.Uint32(data)), true
	case 8:
		return order.Uint64(data), true
	default:
		return 0, false
	}
}

func decodeStringInteger(data []byte, base int) (uint64, bool) {
	text := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
	text = strings.TrimPrefix(text, "0x")
	value, err := strconv.ParseUint(text, base, 64)
	return value, err == nil
}

func bitMask(bits uint64) uint64 {
	if bits >= 64 {
		return ^uint64(0)
	}
	return 1<<bits - 1
}

func summarizeOutputData(data []byte, size uint64) *runtimeDataSummary {
	ret := &runtimeDataSummary{
		Size:         size,
		CapturedSize: uint64(len(data)),
		Hash:         hash.String(data),
		Output:       true,
		Truncated:    uint64(len(data)) < size,
	}
	preview := data
	const maxPreviewBytes = 32
	if len(preview) > maxPreviewBytes {
		preview = preview[:maxPreviewBytes]
		ret.Truncated = true
	}
	ret.PreviewHex = hex.EncodeToString(preview)
	return ret
}

func cloneRuntimeOutputCaptures(captures []*runtimeOutputCapture) []*runtimeOutputCapture {
	if len(captures) == 0 {
		return nil
	}
	ret := make([]*runtimeOutputCapture, len(captures))
	for i, capture := range captures {
		if capture == nil {
			continue
		}
		cloned := *capture
		cloned.Values = make([]*runtimeDecodedOutput, len(capture.Values))
		for j, value := range capture.Values {
			if value == nil {
				continue
			}
			clonedValue := *value
			if value.Value != nil {
				clonedValue.Value = uint64Ptr(*value.Value)
			}
			clonedValue.ValueNames = append([]string(nil), value.ValueNames...)
			if value.DataSummary != nil {
				summary := *value.DataSummary
				clonedValue.DataSummary = &summary
			}
			cloned.Values[j] = &clonedValue
		}
		ret[i] = &cloned
	}
	return ret
}
