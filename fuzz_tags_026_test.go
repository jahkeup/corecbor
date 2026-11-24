// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"testing"
)

// walk026 calls fn on v and every nested value.
func walk026(v Value, depth int, fn func(Value)) {
	if depth > 64 {
		return
	}
	fn(v)
	for _, it := range v.Items {
		walk026(it, depth+1, fn)
	}
	for _, p := range v.Pairs {
		walk026(p.Key, depth+1, fn)
		walk026(p.Value, depth+1, fn)
	}
}

// FuzzTagHelpersNeverPanic: every proposal 026 accessor on arbitrary
// decoded values returns (possibly an error) without panicking, and a
// successful decode round-trips through the matching constructor.
func FuzzTagHelpersNeverPanic(f *testing.F) {
	for _, h := range []string{
		"d825500123456789abcdef0123456789abcdef",
		"d903ec6a313934302d31302d3039", "d86439299b",
		"d83650" + "20010db81234deedbeefcafefacefeed",
		"d836821830" + "4620010db81234", "d8348244c000020118" + "18",
		"d86f49608648016503040201", "d8704481fd5901", "d86e4301011d",
		"d903e9a2011a6530ab52253a000d534e",
		"d903eaa201012239" + "01f3",
		"d9d9f8da6374021243424f52",
		"d81847a2616102616201",
		"d842480000000100000002", "d8464401000000", "d856480000000000000000",
		"d8288281028201f6", "d829820102", "d8504400013c00",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	dec := NewDecoder(WithoutInternalArena())
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := dec.Decode(data)
		if err != nil {
			return
		}
		walk026(v, 0, func(n Value) {
			// RFC 8746 typed arrays (037 C18): the encoded bytes round-trip.
			if a, err := AsTypedArray[uint32](n); err == nil {
				enc := TypedArrayTo(a)
				if n.TagID() == 70 {
					enc = TypedArrayToLE(a)
				}
				if !enc.Equal(n) {
					t.Fatalf("typed array round trip: %v -> %v", n, enc)
				}
			}
			if m, err := AsMultiDimArray(n); err == nil {
				if back, err := MultiDimArrayTo(m); err != nil || !back.Equal(n) {
					t.Fatalf("multi-dimensional array round trip: %v -> %v, %v", n, back, err)
				}
			}
			if items, err := AsHomogeneousArray(n); err == nil {
				if back, err := HomogeneousArrayTo(items); err != nil || !back.Equal(n) {
					t.Fatalf("homogeneous array round trip: %v -> %v, %v", n, back, err)
				}
			}
			_, _ = AsFloat64Array(n)
			_, _ = AsFloat128Array(n)
			if a, err := AsTypedArray[float64](n); err == nil {
				if back, err := AsTypedArray[float64](TypedArrayToLE(a)); err != nil || len(back) != len(a) {
					t.Fatalf("float64 typed array round trip: %v, %v", back, err)
				}
			}
			if u, err := AsUUID(n); err == nil {
				if back, err := AsUUID(UUIDTo(u)); err != nil || back != u {
					t.Fatalf("UUID round trip: %x -> %x, %v", u, back, err)
				}
			}
			if d, err := AsDate(n); err == nil {
				if back, err := AsDate(DaysTo(d)); err != nil || !back.Equal(d) {
					t.Fatalf("date round trip: %v -> %v, %v", d, back, err)
				}
			}
			if a, err := AsIP(n); err == nil {
				if back, err := AsIP(IPTo(a)); err != nil || back != a {
					t.Fatalf("IP round trip: %v -> %v, %v", a, back, err)
				}
			}
			if p, err := AsPrefix(n); err == nil {
				if back, err := AsPrefix(PrefixTo(p)); err != nil || back != p.Masked() {
					t.Fatalf("prefix round trip: %v -> %v, %v", p, back, err)
				}
			}
			if oid, err := AsOID(n); err == nil {
				ov, err := OIDTo(oid)
				if err != nil {
					t.Fatalf("OIDTo(%v): %v", oid, err)
				}
				if back, err := AsOID(ov); err != nil || !back.Equal(oid) {
					t.Fatalf("OID round trip: %v -> %v, %v", oid, back, err)
				}
			}
			if arcs, err := AsRelativeOID(n); err == nil {
				back, err := AsRelativeOID(RelativeOIDTo(arcs))
				if err != nil || len(back) != len(arcs) {
					t.Fatalf("relative OID round trip: %v -> %v, %v", arcs, back, err)
				}
			}
			if et, err := AsExtendedTime(n); err == nil {
				if back, err := AsExtendedTime(ExtendedTimeTo(et)); err != nil || !back.Time.Equal(et.Time) {
					t.Fatalf("extended time round trip: %v -> %v, %v", et.Time, back.Time, err)
				}
			}
			if d, err := AsDuration(n); err == nil {
				if back, err := AsDuration(DurationTo(d)); err != nil || back != d {
					t.Fatalf("duration round trip: %v -> %v, %v", d, back, err)
				}
			}
			if tag, err := AsSequenceLabel(n); err == nil {
				if back, err := AsSequenceLabel(SequenceLabelTo(tag)); err != nil || back != tag {
					t.Fatalf("label round trip: %d -> %d, %v", tag, back, err)
				}
			}
			_, _, _ = dec.DecodeEncodedCBOR(n)
		})
	})
}
