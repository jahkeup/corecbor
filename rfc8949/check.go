// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"fmt"
	"math"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

// checkSerialization verifies that src, one item Decode has already
// accepted (so it is well-formed and within limits), also follows the
// serialization rules opts asks for (proposal 024): RequirePreferred,
// RequireSortedMapKeys, RequireCanonicalNaN.
func checkSerialization(src []byte, opts DecodeOpts) error {
	_, err := checkItem(src, 0, &opts)
	return err
}

func notPreferred(off int, cause error, what string) error {
	if cause != nil {
		return decodeErrDetail(fmt.Errorf("%w: %w", cbor.ErrNotPreferred, cause), off, ": "+what)
	}
	return decodeErrDetail(cbor.ErrNotPreferred, off, ": "+what)
}

func checkItem(src []byte, off int, o *DecodeOpts) (int, error) {
	// A tag's content is checked by looping rather than recursing, so a
	// chain of self-describe tags (which Decode accepts at any length,
	// 037 C1) can't overflow the stack.
	for {
		h := wire.ParseHead(src[off:])
		if h.Major != wire.MajorTag {
			return checkHead(src, off, h, o)
		}
		if o.RequirePreferred && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
			return 0, notPreferred(off, cbor.ErrNonShortest, "non-shortest argument")
		}
		pos := off + h.N
		if o.RequirePreferred && (h.Arg == cbor.TagUnsignedBignum || h.Arg == cbor.TagNegativeBignum) {
			ih := wire.ParseHead(src[pos:])
			if ih.Major == wire.MajorBytes && ih.AI != wire.AIIndefinite {
				content := src[pos+ih.N : pos+ih.N+int(ih.Arg)]
				if len(content) <= 8 {
					return 0, notPreferred(off, nil, "bignum that fits major type 0/1")
				}
				if content[0] == 0 {
					return 0, notPreferred(off, nil, "bignum with leading zero")
				}
			}
		}
		off = pos
	}
}

// checkHead checks the item at off, whose head h is not a tag.
func checkHead(src []byte, off int, h wire.HeadResult, o *DecodeOpts) (int, error) {
	pos := off + h.N
	indef := h.AI == wire.AIIndefinite

	if o.RequirePreferred && h.Major != wire.MajorOther && h.AI >= wire.AI1Byte && h.AI <= wire.AI8Bytes && !h.IsShortest() {
		return 0, notPreferred(off, cbor.ErrNonShortest, "non-shortest argument")
	}
	if o.RequirePreferred && indef {
		return 0, notPreferred(off, cbor.ErrIndefiniteLength, "indefinite length")
	}

	switch h.Major {
	case wire.MajorUint, wire.MajorNegInt:
		return pos, nil

	case wire.MajorBytes, wire.MajorText:
		if !indef {
			return pos + int(h.Arg), nil
		}
		for src[pos] != wire.BreakCode {
			var err error
			if pos, err = checkItem(src, pos, o); err != nil {
				return 0, err
			}
		}
		return pos + 1, nil

	case wire.MajorArray:
		if indef {
			for src[pos] != wire.BreakCode {
				var err error
				if pos, err = checkItem(src, pos, o); err != nil {
					return 0, err
				}
			}
			return pos + 1, nil
		}
		for range h.Arg {
			var err error
			if pos, err = checkItem(src, pos, o); err != nil {
				return 0, err
			}
		}
		return pos, nil

	case wire.MajorMap:
		var prev []byte
		for i := uint64(0); indef || i < h.Arg; i++ {
			if indef && src[pos] == wire.BreakCode {
				return pos + 1, nil
			}
			keyOff := pos
			next, err := checkItem(src, pos, o)
			if err != nil {
				return 0, err
			}
			key := src[keyOff:next]
			if o.RequireSortedMapKeys && i > 0 {
				switch c := bytes.Compare(prev, key); {
				case c == 0:
					return 0, decodeErr(fmt.Errorf("%w: %w", cbor.ErrNotDeterministic, cbor.ErrDuplicateMapKey), keyOff)
				case c > 0:
					return 0, decodeErrDetail(cbor.ErrNotDeterministic, keyOff, ": map keys not in bytewise-lexicographic order")
				}
			}
			prev = key
			if pos, err = checkItem(src, next, o); err != nil {
				return 0, err
			}
		}
		return pos, nil

	default: // major type 7
		return pos, checkFloat(h, off, o)
	}
}

// checkFloat applies the float rules: shortest width that preserves the
// value, NaN payload included (RFC 8949 §4.1), and with
// RequireCanonicalNaN only f97e00 as NaN.
func checkFloat(h wire.HeadResult, off int, o *DecodeOpts) error {
	var (
		f        float64
		nan      bool
		narrower bool // an exact narrower encoding exists
	)
	switch h.AI {
	case wire.AI2Bytes:
		b := uint16(h.Arg)
		nan = b&0x7c00 == 0x7c00 && b&0x3ff != 0
		if nan && o.RequireCanonicalNaN && b != 0x7e00 {
			return notPreferred(off, nil, "NaN other than f97e00")
		}
		return nil
	case wire.AI4Bytes:
		b := uint32(h.Arg)
		f = float64(math.Float32frombits(b))
		nan = b&0x7f800000 == 0x7f800000 && b&0x7fffff != 0
		if nan {
			narrower = b&0x1fff == 0 // payload fits a half significand
		} else {
			_, narrower = wire.EncodeFloat16(f)
		}
	case wire.AI8Bytes:
		f = math.Float64frombits(h.Arg)
		nan = math.IsNaN(f)
		if nan {
			narrower = h.Arg&(1<<29-1) == 0 // payload fits a single significand
		} else if _, ok := wire.EncodeFloat16(f); ok {
			narrower = true
		} else {
			narrower = wire.CanFloat32Lossless(f)
		}
	default:
		return nil // simple values
	}
	if nan && o.RequireCanonicalNaN {
		return notPreferred(off, nil, "NaN other than f97e00")
	}
	if o.RequirePreferred && narrower {
		return notPreferred(off, cbor.ErrNonShortest, "float wider than needed")
	}
	return nil
}
