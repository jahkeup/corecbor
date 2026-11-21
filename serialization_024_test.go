// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// Proposal 024 acceptance tests.

var deterministicModes = []Mode{ModeCoreDeterministic, ModeCanonical, ModeCTAP2}

func encHex(t *testing.T, enc *Encoder, v Value) string {
	t.Helper()
	b, err := enc.Encode(nil, v)
	if err != nil {
		t.Fatalf("Encode(%s): %v", DiagnosticValue(v), err)
	}
	return hex.EncodeToString(b)
}

func TestCTAP2NaNNormalized(t *testing.T) {
	enc := New(ModeCTAP2, AllowNonFiniteFloats())
	for _, v := range []Value{
		Float64(math.NaN()),
		Float64(math.Float64frombits(0x7ff0000000000001)),
		Float64(math.Float64frombits(0xfff8000000000000)),
		Float32(math.Float32frombits(0x7fc00001)),
	} {
		if got := encHex(t, enc, v); got != "fb7ff8000000000000" {
			t.Errorf("CTAP2 NaN %x: got %s", v.Num, got)
		}
	}
}

func TestBignumPreferred(t *testing.T) {
	big9 := append([]byte{0x00}, bytes.Repeat([]byte{0xff}, 9)...) // leading zero, 9 significant bytes
	for _, mode := range deterministicModes {
		enc := New(mode)
		cases := []struct {
			v    Value
			want string
		}{
			{cbor.MakeTag(2, Bytes([]byte{0x00, 0x01})), "01"},
			{cbor.MakeTag(2, Bytes(nil)), "00"},
			{cbor.MakeTag(3, Bytes([]byte{0x04})), "24"},
			{cbor.MakeTag(2, Bytes(bytes.Repeat([]byte{0xff}, 8))), "1bffffffffffffffff"},
			{cbor.MakeTag(2, Bytes(big9)), "c249" + hex.EncodeToString(big9[1:])},
			{cbor.MakeTag(3, Bytes(big9)), "c349" + hex.EncodeToString(big9[1:])},
		}
		for _, tc := range cases {
			if got := encHex(t, enc, tc.v); got != tc.want {
				t.Errorf("mode %d %s: got %s, want %s", mode, DiagnosticValue(tc.v), got, tc.want)
			}
		}
	}
	// Permissive keeps what it was given.
	if got := encHex(t, New(ModePermissive), cbor.MakeTag(2, Bytes([]byte{0x00, 0x01}))); got != "c2420001" {
		t.Errorf("Permissive: got %s, want c2420001", got)
	}
}

func TestBigIntToPreferred(t *testing.T) {
	cases := []struct {
		n    *big.Int
		want Value
	}{
		{big.NewInt(-5), NegInt(4)},
		{big.NewInt(0), Uint(0)},
		{new(big.Int).SetUint64(math.MaxUint64), Uint(math.MaxUint64)},
	}
	for _, tc := range cases {
		if got := BigIntToPreferred(tc.n); got.Kind != tc.want.Kind || got.Num != tc.want.Num {
			t.Errorf("BigIntToPreferred(%v) = %s", tc.n, DiagnosticValue(got))
		}
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 64)
	if got := BigIntToPreferred(huge); got.Kind != cbor.KindTag || got.TagID() != 2 {
		t.Errorf("BigIntToPreferred(2^64) = %s, want tag 2", DiagnosticValue(got))
	}
	// BigIntTo keeps v0.2.2 semantics; deterministic encoding reduces it.
	v := BigIntTo(big.NewInt(-5))
	if v.Kind != cbor.KindTag {
		t.Fatalf("BigIntTo(-5) kind = %d, want tag", v.Kind)
	}
	if got := encHex(t, New(ModeCoreDeterministic), v); got != "24" {
		t.Errorf("Encode(BigIntTo(-5)) = %s, want 24", got)
	}
}

func TestCompatBignumPassthrough(t *testing.T) {
	v := cbor.MakeTag(2, Bytes([]byte{0x00, 0x01}))
	for _, opt := range []Option{WithLegacyBignumPassthrough(), CompatV02()} {
		if got := encHex(t, New(ModeCoreDeterministic, opt), v); got != "c2420001" {
			t.Errorf("legacy passthrough: got %s, want c2420001", got)
		}
	}
}

func TestUnmarshalBigIntFromInt(t *testing.T) {
	for _, h := range []string{"01", "c24101"} {
		var n big.Int
		if err := Unmarshal(mustHex(t, h), &n); err != nil || n.Int64() != 1 {
			t.Errorf("Unmarshal(%s, &big.Int) = %v, %v", h, &n, err)
		}
		var p *big.Int
		if err := Unmarshal(mustHex(t, h), &p); err != nil || p.Int64() != 1 {
			t.Errorf("Unmarshal(%s, &*big.Int) = %v, %v", h, p, err)
		}
	}
	var n big.Int
	if err := Unmarshal(mustHex(t, "24"), &n); err != nil || n.Int64() != -5 {
		t.Errorf("Unmarshal(24, &big.Int) = %v, %v", &n, err)
	}
	// Round trip through Marshal, which now writes small values as integers.
	in := big.NewInt(-12345)
	b, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out big.Int
	if err := Unmarshal(b, &out); err != nil || out.Cmp(in) != 0 {
		t.Fatalf("round trip %v -> %x -> %v, %v", in, b, &out, err)
	}
}

func TestPreferredPlusMode(t *testing.T) {
	enc := New(ModePreferredPlus)
	m := MakeMap(MapEntry{Key: Text("b"), Value: Uint(1)}, MapEntry{Key: Text("a"), Value: Float64(1.0)})
	if got := encHex(t, enc, m); got != "a2616201616"+"1f93c00" {
		t.Errorf("PreferredPlus map = %s, want insertion order with f93c00", got)
	}
	core := New(ModeCoreDeterministic, AllowNonFiniteFloats())
	pp := New(ModePreferredPlus, AllowNonFiniteFloats())
	for _, v := range []Value{
		Float64(1.5), Float32(100000), Float64(math.NaN()), Float64(math.Inf(-1)),
		cbor.MakeTag(2, Bytes([]byte{0, 0, 7})), Uint(1000), Text("x"),
	} {
		if a, b := encHex(t, core, v), encHex(t, pp, v); a != b {
			t.Errorf("%s: PreferredPlus %s, CoreDeterministic %s", DiagnosticValue(v), b, a)
		}
	}
	var buf bytes.Buffer
	if err := enc.Stream(&buf).BeginArray(-1); !errors.Is(err, ErrIndefiniteNotPermitted) {
		t.Errorf("PreferredPlus indefinite stream: %v", err)
	}
}

func TestRequireDeterministicUnsorted(t *testing.T) {
	_, err := NewDecoder(RequireDeterministic()).Decode(mustHex(t, "a2616201616102"))
	if !errors.Is(err, ErrNotDeterministic) {
		t.Fatalf("err = %v, want ErrNotDeterministic", err)
	}
	_, err = NewDecoder(RequireDeterministic()).Decode(mustHex(t, "a2616101616102"))
	if !errors.Is(err, ErrNotDeterministic) || !errors.Is(err, ErrDuplicateMapKey) {
		t.Fatalf("dup: err = %v, want ErrNotDeterministic+ErrDuplicateMapKey", err)
	}
	if _, err := NewDecoder(RequireDeterministic()).Decode(mustHex(t, "a2616101616202")); err != nil {
		t.Fatalf("sorted map: %v", err)
	}
}

func TestRequirePreferredPlus(t *testing.T) {
	cases := []struct {
		hex   string
		cause error
	}{
		{"fa3f800000", ErrNonShortest},         // 1.0 as single
		{"f97e01", nil},                        // NaN with payload
		{"c2420001", nil},                      // bignum, leading zero, fits uint
		{"9fff", ErrIndefiniteLength},          // indefinite array
		{"1801", ErrNonShortest},               // 1 with 1-byte argument
		{"fb3ff0000000000000", ErrNonShortest}, // 1.0 as double
		{"fb7ff8000000000000", nil},            // NaN, not f97e00
		{"f9fe00", nil},                        // negative NaN
	}
	dec := NewDecoder(RequirePreferredPlus())
	for _, tc := range cases {
		_, err := dec.Decode(mustHex(t, tc.hex))
		if !errors.Is(err, ErrNotPreferred) {
			t.Errorf("%s: err = %v, want ErrNotPreferred", tc.hex, err)
		}
		if tc.cause != nil && !errors.Is(err, tc.cause) {
			t.Errorf("%s: err = %v, want also %v", tc.hex, err, tc.cause)
		}
	}
	for _, h := range []string{"f97e00", "f93c00", "fa47c35000", "c249010000000000000000", "a2616201616102"} {
		if _, err := dec.Decode(mustHex(t, h)); err != nil {
			t.Errorf("%s: %v, want accepted", h, err)
		}
	}
	// RequireDeterministic preserves NaN payloads in the shortest width
	// (RFC 8949 §4.1) and doesn't impose the draft's f97e00 rule.
	det := NewDecoder(RequireDeterministic())
	if _, err := det.Decode(mustHex(t, "f97e01")); err != nil {
		t.Errorf("RequireDeterministic f97e01: %v", err)
	}
	if _, err := det.Decode(mustHex(t, "fa7fc00000")); !errors.Is(err, ErrNotPreferred) {
		t.Errorf("RequireDeterministic f32 NaN representable in f16: %v", err)
	}
}

func TestDuplicateKeyFloatEquivalence(t *testing.T) {
	dec := NewDecoder(RejectDuplicateMapKeys())
	for _, h := range []string{
		"a2f97e0001f97e0002",     // {NaN: 1, NaN: 2}
		"a2f9000001f9800002",     // {+0: 1, -0: 2}
		"a2f93c0001fa3f80000002", // {1.0 (f16): 1, 1.0 (f32): 2}
		"a2f97e0001fa7fc0000002", // NaN f16 vs same NaN as f32
	} {
		if _, err := dec.Decode(mustHex(t, h)); !errors.Is(err, ErrDuplicateMapKey) {
			t.Errorf("%s: err = %v, want ErrDuplicateMapKey", h, err)
		}
	}
	for _, h := range []string{
		"a2f97e0001f9fe0002", // sign bits differ (erratum 8589)
		"a2f97e0001f97e0102", // payloads differ
	} {
		if _, err := dec.Decode(mustHex(t, h)); err != nil {
			t.Errorf("%s: %v, want distinct keys", h, err)
		}
	}
	// Integer 1 and float 1.0 are different keys (RFC 8949 §5.6.1).
	if _, err := dec.Decode(mustHex(t, "a20101f93c0002")); err != nil {
		t.Errorf("{1: 1, 1.0: 2}: %v, want distinct keys", err)
	}
}

func TestCompatFloatKeyEquality(t *testing.T) {
	h := mustHex(t, "a2f93c0001fa3f80000002")
	for _, opt := range []DecoderOption{WithLegacyFloatKeyEquality(), CompatV02Decoding()} {
		if _, err := NewDecoder(RejectDuplicateMapKeys(), opt).Decode(h); err != nil {
			t.Errorf("legacy float equality: %v, want accepted", err)
		}
	}
	if _, err := NewDecoder(RejectDuplicateMapKeys()).Decode(h); !errors.Is(err, ErrDuplicateMapKey) {
		t.Errorf("default: %v, want ErrDuplicateMapKey", err)
	}
}

// mapWith builds a map of n entries whose first two keys are k1 and k2
// (encoded) and whose remaining keys are distinct filler text keys.
func mapWith(n int, k1, k2 string) []byte {
	b := []byte{0xb8, byte(n)}
	b = append(b, mustHexB(k1)...)
	b = append(b, 0x61, 'a')
	b = append(b, mustHexB(k2)...)
	b = append(b, 0x61, 'b')
	for i := 2; i < n; i++ {
		b = append(b, 0x62, 'f', byte('a'+i), 0xf6)
	}
	return b
}

func mustHexB(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestKeyIdentityMapSizeIndependent(t *testing.T) {
	for _, n := range []int{2, 16, 17, 40} {
		src := mapWith(n, "01", "1801") // 1 and 1 (non-shortest)
		v, err := NewDecoder().Decode(src)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Pairs) != n-1 || v.Pairs[0].Value.Str != "b" {
			t.Errorf("n=%d: last-write-wins: %d pairs, first value %q", n, len(v.Pairs), v.Pairs[0].Value.Str)
		}
		if _, err := NewDecoder(RejectDuplicateMapKeys()).Decode(src); !errors.Is(err, ErrDuplicateMapKey) {
			t.Errorf("n=%d: reject: %v", n, err)
		}
	}
}

func TestKeyIdentityEncoded(t *testing.T) {
	for _, n := range []int{2, 17} {
		distinct := mapWith(n, "01", "1801")
		v, err := NewDecoder(WithMapKeyIdentity(KeyIdentityEncoded)).Decode(distinct)
		if err != nil || len(v.Pairs) != n {
			t.Errorf("n=%d: encoded identity keeps 01 and 1801: %d pairs, %v", n, len(v.Pairs), err)
		}
		if _, err := NewDecoder(WithMapKeyIdentity(KeyIdentityEncoded), RejectDuplicateMapKeys()).Decode(distinct); err != nil {
			t.Errorf("n=%d: encoded identity + reject: %v", n, err)
		}
		same := mapWith(n, "01", "01")
		if _, err := NewDecoder(WithMapKeyIdentity(KeyIdentityEncoded), RejectDuplicateMapKeys()).Decode(same); !errors.Is(err, ErrDuplicateMapKey) {
			t.Errorf("n=%d: byte-identical repeat: %v", n, err)
		}
		v, err = NewDecoder(WithMapKeyIdentity(KeyIdentityEncoded)).Decode(same)
		if err != nil || len(v.Pairs) != n-1 || v.Pairs[0].Value.Str != "b" {
			t.Errorf("n=%d: encoded last-write-wins: %v", n, err)
		}
	}
}

func TestKeepDuplicateMapKeys(t *testing.T) {
	for _, id := range []KeyIdentity{KeyIdentityValue, KeyIdentityEncoded} {
		for _, n := range []int{2, 17} {
			src := mapWith(n, "01", "01")
			v, err := NewDecoder(KeepDuplicateMapKeys(), WithMapKeyIdentity(id)).Decode(src)
			if err != nil || len(v.Pairs) != n || v.Pairs[0].Value.Str != "a" || v.Pairs[1].Value.Str != "b" {
				t.Errorf("id=%d n=%d: keep: %v", id, n, err)
			}
		}
	}
	_, err := NewDecoder(KeepDuplicateMapKeys(), RejectDuplicateMapKeys()).Decode(mustHex(t, "a0"))
	if !errors.Is(err, ErrInvalidOption) {
		t.Errorf("keep+reject: %v, want ErrInvalidOption", err)
	}
	// Re-encoding kept duplicates deterministically fails instead of merging.
	v, _ := NewDecoder(KeepDuplicateMapKeys(), WithMapKeyIdentity(KeyIdentityEncoded)).Decode(mustHex(t, "a2016161180161"+"62"))
	if _, err := New(ModeCoreDeterministic).Encode(nil, v); !errors.Is(err, ErrDuplicateMapKey) {
		t.Errorf("deterministic re-encode of kept duplicates: %v", err)
	}
}

func TestStrictVsDeterministicPreset(t *testing.T) {
	src := mustHex(t, "a2616201616102")
	if _, err := StrictDecoder().Decode(src); err != nil {
		t.Errorf("StrictDecoder: %v, want accepted", err)
	}
	if _, err := DeterministicDecoder().Decode(src); !errors.Is(err, ErrNotDeterministic) {
		t.Errorf("DeterministicDecoder: %v, want ErrNotDeterministic", err)
	}
}

// Half-precision NaN payloads survive decode, so distinct NaNs stay
// distinct keys and Permissive re-encoding keeps the payload.
func TestHalfNaNPayloadPreserved(t *testing.T) {
	v, err := NewDecoder().Decode(mustHex(t, "f97e01"))
	if err != nil {
		t.Fatal(err)
	}
	if bits := math.Float64bits(v.Float64Val()); bits != 0x7ff8040000000000 {
		t.Errorf("f97e01 decoded bits %016x", bits)
	}
	if got := encHex(t, New(ModeCoreDeterministic, AllowNonFiniteFloats()), Float64(math.Float64frombits(0x7ff8000000000000))); got != "f97e00" {
		t.Errorf("canonical NaN = %s", got)
	}
}

// The raw-span path (Unmarshalers, proposal 022) merges repeated keys
// exactly as the decoder does under the configured key identity and
// duplicate policy. A NaN-keyed Go map makes any disagreement visible:
// every NaN key is a distinct Go map entry.
func TestRawPathFollowsKeyIdentity(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		opts []DecoderOption
		want int // Go map entries
	}{
		{"value-identity-nan", "a2f97e004101f97e004102", nil, 1},
		{"value-identity-nan-widths", "a2f97e004101fa7fc000004102", nil, 1},
		{"value-identity-distinct-nan", "a2f97e004101f97e014102", nil, 2},
		{"keep", "a2f97e004101f97e004102", []DecoderOption{KeepDuplicateMapKeys()}, 2},
		{"encoded-identity-widths", "a2f97e004101fa7fc000004102", []DecoderOption{WithMapKeyIdentity(KeyIdentityEncoded)}, 2},
		{"indefinite", "bff97e004101f97e004102ff", nil, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := NewDecoder(tc.opts...)
			var raw map[float64]RawMessage
			if err := dec.Unmarshal(mustHex(t, tc.hex), &raw); err != nil {
				t.Fatal(err)
			}
			var plain map[float64][]byte
			if err := dec.Unmarshal(mustHex(t, tc.hex), &plain); err != nil {
				t.Fatal(err)
			}
			if len(raw) != tc.want || len(plain) != tc.want {
				t.Fatalf("entries: raw %d, Value path %d, want %d", len(raw), len(plain), tc.want)
			}
			if tc.want == 1 {
				for _, v := range raw {
					if hex.EncodeToString(v) != "4102" {
						t.Fatalf("merged value = %x, want last write 4102", []byte(v))
					}
				}
			}
		})
	}
}
