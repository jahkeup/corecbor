// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package wire

import "encoding/binary"

// Major type constants (high 3 bits of initial byte).
const (
	MajorUint   byte = 0 << 5 // 0x00
	MajorNegInt byte = 1 << 5 // 0x20
	MajorBytes  byte = 2 << 5 // 0x40
	MajorText   byte = 3 << 5 // 0x60
	MajorArray  byte = 4 << 5 // 0x80
	MajorMap    byte = 5 << 5 // 0xa0
	MajorTag    byte = 6 << 5 // 0xc0
	MajorOther  byte = 7 << 5 // 0xe0
)

// Additional information values with special meaning.
const (
	AI1Byte      byte = 24
	AI2Bytes     byte = 25
	AI4Bytes     byte = 26
	AI8Bytes     byte = 27
	AIIndefinite byte = 31
)

// Simple value encodings in major type 7.
const (
	SimpleFalse     byte = MajorOther | 20
	SimpleTrue      byte = MajorOther | 21
	SimpleNull      byte = MajorOther | 22
	SimpleUndefined byte = MajorOther | 23
	SimpleOneByte   byte = MajorOther | AI1Byte // followed by 1 byte (32-255)
	Float16Marker   byte = MajorOther | AI2Bytes
	Float32Marker   byte = MajorOther | AI4Bytes
	Float64Marker   byte = MajorOther | AI8Bytes
	BreakCode       byte = MajorOther | AIIndefinite // 0xff
)

// AppendHead appends the CBOR head (major type + argument) using the
// shortest encoding. dst may be nil.
func AppendHead(dst []byte, major byte, arg uint64) []byte {
	switch {
	case arg < 24:
		return append(dst, major|byte(arg))
	case arg <= 0xff:
		return append(dst, major|AI1Byte, byte(arg))
	case arg <= 0xffff:
		return binary.BigEndian.AppendUint16(append(dst, major|AI2Bytes), uint16(arg))
	case arg <= 0xffffffff:
		return binary.BigEndian.AppendUint32(append(dst, major|AI4Bytes), uint32(arg))
	default:
		return binary.BigEndian.AppendUint64(append(dst, major|AI8Bytes), arg)
	}
}

// HeadResult is the parsed result of a CBOR initial byte + argument.
type HeadResult struct {
	Major byte   // major type (shifted, e.g. MajorUint = 0x00)
	AI    byte   // raw additional information (0-31)
	Arg   uint64 // decoded argument value
	N     int    // total bytes consumed (head size: 1, 2, 3, 5, or 9)
}

// ParseHead reads the CBOR head from src. Returns the parsed result.
// If src is too short, N is 0 (caller should check).
func ParseHead(src []byte) HeadResult {
	if len(src) == 0 {
		return HeadResult{}
	}
	ib := src[0]
	major := ib & 0xe0
	ai := ib & 0x1f

	switch {
	case ai < 24:
		return HeadResult{Major: major, AI: ai, Arg: uint64(ai), N: 1}
	case ai == AI1Byte:
		if len(src) < 2 {
			return HeadResult{}
		}
		return HeadResult{Major: major, AI: ai, Arg: uint64(src[1]), N: 2}
	case ai == AI2Bytes:
		if len(src) < 3 {
			return HeadResult{}
		}
		return HeadResult{Major: major, AI: ai, Arg: uint64(binary.BigEndian.Uint16(src[1:])), N: 3}
	case ai == AI4Bytes:
		if len(src) < 5 {
			return HeadResult{}
		}
		return HeadResult{Major: major, AI: ai, Arg: uint64(binary.BigEndian.Uint32(src[1:])), N: 5}
	case ai == AI8Bytes:
		if len(src) < 9 {
			return HeadResult{}
		}
		return HeadResult{Major: major, AI: ai, Arg: binary.BigEndian.Uint64(src[1:]), N: 9}
	default:
		// ai 28-30 are reserved; ai 31 is indefinite (handled by caller).
		// Return with N=1 so caller can inspect AI.
		return HeadResult{Major: major, AI: ai, Arg: 0, N: 1}
	}
}

// IsShortest reports whether the argument encoding in h uses the
// minimum number of bytes (RFC 8949 §4.2.1 preferred serialization).
func (h HeadResult) IsShortest() bool {
	switch h.AI {
	case AI1Byte:
		return h.Arg >= 24
	case AI2Bytes:
		return h.Arg > 0xff
	case AI4Bytes:
		return h.Arg > 0xffff
	case AI8Bytes:
		return h.Arg > 0xffffffff
	default:
		return true // inline (0-23) or special (28-31)
	}
}
