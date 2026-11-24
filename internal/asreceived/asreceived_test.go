// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package asreceived

import (
	"encoding/hex"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

func decode(t *testing.T, h string) ([]byte, cbor.Value) {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := rfc8949.Decode(b, rfc8949.DecodeOpts{})
	if err != nil {
		t.Fatalf("Decode(%s): %v", h, err)
	}
	return b, v
}

func TestNonCanonicalNaN(t *testing.T) {
	for h, want := range map[string]bool{
		"f97e00":               false, // the quiet NaN deterministic encoding writes
		"fa7fc00000":           false,
		"fb7ff8000000000000":   false,
		"f97c00":               false, // +Inf is exact in any width
		"fa3fc00000":           false,
		"f97e01":               true,
		"f9fe00":               true, // sign bit
		"fa7fc00001":           true,
		"fb7ff8000000000001":   true,
		"8201f97e01":           true,
		"a1f97e0101":           true, // as a map key
		"a101fa7fc00001":       true,
		"c1fb7ff8000000000001": true,
	} {
		if _, v := decode(t, h); NonCanonicalNaN(v) != want {
			t.Errorf("NonCanonicalNaN(%s) = %v, want %v", h, !want, want)
		}
	}
}

func TestIntegerBignum(t *testing.T) {
	for h, want := range map[string]bool{
		"c240":                   true,
		"c24101":                 true,
		"c3410a":                 true,
		"c248ffffffffffffffff":   true,
		"c249000000000000000001": true,
		"c249010000000000000000": false, // 2^64
		"01":                     false,
		"c14101":                 false, // tag 1 around bytes
	} {
		if _, v := decode(t, h); IntegerBignum(v) != want {
			t.Errorf("IntegerBignum(%s) = %v, want %v", h, !want, want)
		}
	}
}

func TestMapSpans(t *testing.T) {
	for _, h := range []string{
		"a2c24101f6" + "1801f97e01", // definite; non-shortest key kept
		"bfc24101f6" + "1801f97e01ff",
		"d9d9f7" + "a2c24101f6" + "1801f97e01",
	} {
		b, _ := hex.DecodeString(h)
		spans, err := MapSpans(b)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		want := [][2]string{{"c24101", "f6"}, {"1801", "f97e01"}}
		if len(spans) != len(want) {
			t.Fatalf("%s: %d spans, want %d", h, len(spans), len(want))
		}
		for i, s := range spans {
			if hex.EncodeToString(s.Key) != want[i][0] || hex.EncodeToString(s.Value) != want[i][1] {
				t.Errorf("%s: span %d = %x/%x, want %s/%s", h, i, s.Key, s.Value, want[i][0], want[i][1])
			}
		}
	}
	if _, err := MapSpans([]byte{0x80}); err == nil {
		t.Error("MapSpans(array) succeeded")
	}
}

func TestOneItem(t *testing.T) {
	for h, want := range map[string]bool{
		"f97e01": true, "c24101": true, "a0": true,
		"": false, "0101": false, "c2": false, "ff": false,
	} {
		b, _ := hex.DecodeString(h)
		if OneItem(b) != want {
			t.Errorf("OneItem(%s) = %v, want %v", h, !want, want)
		}
	}
}

func TestArraySpans(t *testing.T) {
	for _, h := range []string{"82a101f97e01a0", "9fa101f97e01a0ff", "d9d9f782a101f97e01a0"} {
		b, _ := hex.DecodeString(h)
		items, err := ArraySpans(b)
		if err != nil || len(items) != 2 || hex.EncodeToString(items[0]) != "a101f97e01" || hex.EncodeToString(items[1]) != "a0" {
			t.Fatalf("%s: ArraySpans = %x, %v", h, items, err)
		}
	}
	if _, err := ArraySpans([]byte{0xa0}); err == nil {
		t.Error("ArraySpans(map) succeeded")
	}
}

func TestBignumInt64(t *testing.T) {
	for h, want := range map[string]int64{"c240": 0, "c24105": 5, "c243000105": 261, "c3410a": -11, "c340": -1} {
		_, v := decode(t, h)
		if n, ok := BignumInt64(v); !ok || n != want {
			t.Errorf("BignumInt64(%s) = %d, %v; want %d", h, n, ok, want)
		}
	}
	for _, h := range []string{"c248ffffffffffffffff", "c14105", "05"} {
		if _, v := decode(t, h); func() bool { _, ok := BignumInt64(v); return ok }() {
			t.Errorf("BignumInt64(%s) ok", h)
		}
	}
}
