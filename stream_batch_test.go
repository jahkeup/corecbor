// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

var allModes = []Mode{ModePermissive, ModeCoreDeterministic, ModeCanonical, ModeCTAP2}

// streamValue writes v through s item by item, pre-sorting map keys
// for deterministic modes the way Encode would.
func streamValue(s *StreamEncoder, enc *Encoder, v Value) error {
	switch v.Kind {
	case cbor.KindArray:
		if err := s.BeginArray(len(v.Items)); err != nil {
			return err
		}
		for _, it := range v.Items {
			if err := streamValue(s, enc, it); err != nil {
				return err
			}
		}
		return s.EndContainer()
	case cbor.KindMap:
		pairs := slices.Clone(v.Pairs)
		if enc.mode != ModePermissive {
			keys := make(map[int][]byte, len(pairs))
			for i := range pairs {
				k, err := enc.Encode(nil, pairs[i].Key)
				if err != nil {
					return err
				}
				keys[i] = k
			}
			idx := make([]int, len(pairs))
			for i := range idx {
				idx[i] = i
			}
			lengthFirst := enc.mode == ModeCanonical || enc.mode == ModeCTAP2
			slices.SortStableFunc(idx, func(a, b int) int {
				ka, kb := keys[a], keys[b]
				if lengthFirst && len(ka) != len(kb) {
					return len(ka) - len(kb)
				}
				return bytes.Compare(ka, kb)
			})
			sorted := make([]MapEntry, len(pairs))
			for i, j := range idx {
				sorted[i] = pairs[j]
			}
			pairs = sorted
		}
		if err := s.BeginMap(len(pairs)); err != nil {
			return err
		}
		for _, p := range pairs {
			if err := streamValue(s, enc, p.Key); err != nil {
				return err
			}
			if err := streamValue(s, enc, p.Value); err != nil {
				return err
			}
		}
		return s.EndContainer()
	case cbor.KindTag:
		// Bignums go through WriteValue so deterministic modes write the
		// preferred form, as Encode does (WriteTag can't rewrite them).
		if (v.TagID() == cbor.TagUnsignedBignum || v.TagID() == cbor.TagNegativeBignum) &&
			v.TagInner().Kind == cbor.KindBytes {
			return s.WriteValue(v)
		}
		if err := s.WriteTag(v.TagID()); err != nil {
			return err
		}
		return streamValue(s, enc, v.TagInner())
	default:
		return s.WriteValue(v)
	}
}

// D18: WriteValue applies the mode's float rules and UTF-8 validation,
// matching Encode.
func TestD18_WriteValueMatchesEncode(t *testing.T) {
	vals := []Value{
		Float64(1.0), Float64(1.5), Float64(100000.0), Float64(math.Pi),
		Float32(1.0), Float32(0.1), Float64(math.Copysign(0, -1)),
		Text("ok"),
	}
	for _, mode := range allModes {
		enc := New(mode)
		for _, v := range vals {
			want, err := enc.Encode(nil, v)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := enc.Stream(&buf).WriteValue(v); err != nil {
				t.Fatalf("mode %d %s: %v", mode, DiagnosticValue(v), err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("mode %d %s: stream %x, Encode %x", mode, DiagnosticValue(v), buf.Bytes(), want)
			}
		}
		for _, v := range []Value{Float64(math.NaN()), Float64(math.Inf(1)), Text("\xff")} {
			var buf bytes.Buffer
			err := enc.Stream(&buf).WriteValue(v)
			if !errors.Is(err, ErrNonFiniteFloat) && !errors.Is(err, ErrInvalidUTF8) {
				t.Errorf("mode %d %s: err = %v, want rejection", mode, DiagnosticValue(v), err)
			}
		}
	}
}

// FuzzStreamMatchesBatch: any decodable value, streamed item by item
// (map keys pre-sorted for deterministic modes), yields the same bytes
// as Encode in every mode.
func FuzzStreamMatchesBatch(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}
	dec := NewDecoder(WithoutInternalArena())
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := dec.Decode(data)
		if err != nil {
			return
		}
		for _, mode := range allModes {
			enc := New(mode, AllowNonFiniteFloats(), AllowInvalidUTF8())
			want, err := enc.Encode(nil, v)
			if err != nil {
				continue
			}
			var buf bytes.Buffer
			if err := streamValue(enc.Stream(&buf), enc, v); err != nil {
				t.Fatalf("mode %d: stream: %v (Encode succeeded: %x)", mode, err, want)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Fatalf("mode %d: stream %x, Encode %x", mode, buf.Bytes(), want)
			}
		}
	})
}
