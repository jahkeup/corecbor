// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

// Proposal 021: regression tests for the core codec safety fixes.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// D1: package-level Marshal/Unmarshal are safe for concurrent use.
// Run under -race.
func TestD1_PackageLevelConcurrency(t *testing.T) {
	in := map[string]any{"b": []any{"x", "y"}, "a": map[string]int{"z": 1, "y": 2}}
	want, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				got, err := Marshal(in)
				if err != nil || string(got) != string(want) {
					t.Errorf("Marshal = %x, %v; want %x", got, err, want)
					return
				}
				var v cbor.Value
				if err := Unmarshal(want, &v); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// D2: a cbor.Value stored by Unmarshal must not change when the
// decoder is reused.
func TestD2_UnmarshalValueDoesNotAliasArena(t *testing.T) {
	type S struct {
		X cbor.Value `cbor:"x"`
		Y any        `cbor:"y"`
	}
	a, _ := Marshal(map[string]any{"x": []any{"aaaa", "bbbb"}, "y": cbor.MakeTag(99, MakeArray(Text("p")))})
	b, _ := Marshal(map[string]any{"x": []any{"zzzz", "yyyy"}, "y": cbor.MakeTag(99, MakeArray(Text("q")))})
	for name, dec := range map[string]*Decoder{
		"package": nil,
		"decoder": NewDecoder(),
	} {
		t.Run(name, func(t *testing.T) {
			unmarshal := Unmarshal
			if dec != nil {
				unmarshal = dec.Unmarshal
			}
			var s1, s2 S
			if err := unmarshal(a, &s1); err != nil {
				t.Fatal(err)
			}
			if err := unmarshal(b, &s2); err != nil {
				t.Fatal(err)
			}
			if got := s1.X.Items[0].Str + s1.X.Items[1].Str; got != "aaaabbbb" {
				t.Fatalf("s1.X = %q after second Unmarshal", got)
			}
			tag := s1.Y.(cbor.Value)
			if got := tag.TagInner().Items[0].Str; got != "p" {
				t.Fatalf("s1.Y inner = %q after second Unmarshal", got)
			}
		})
	}
}

// D3: maps with non-text keys decode into map[any]any without panicking.
func TestD3_AnyMapKeys(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		key  any
	}{
		{"bytes", "a1410101", cbor.ByteKey("\x01")},
		{"array", "a1820102" + "01", cbor.EncodedKey("\x82\x01\x02")},
		{"map", "a1a1010201", cbor.EncodedKey("\xa1\x01\x02")},
		{"tag", "a1c10101", cbor.EncodedKey("\xc1\x01")},
		{"negint-min", "a13bffffffffffffffff01", cbor.EncodedKey("\x3b\xff\xff\xff\xff\xff\xff\xff\xff")},
		// Unchanged from v0.2.2: scalar keys keep their Go types.
		{"uint", "a10101", uint64(1)},
		{"negint", "a12001", int64(-1)},
		{"null", "a1f601", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			if err := Unmarshal(mustHex(t, tc.hex), &v); err != nil {
				t.Fatal(err)
			}
			m, ok := v.(map[any]any)
			if !ok {
				t.Fatalf("got %T, want map[any]any", v)
			}
			if _, ok := m[tc.key]; !ok || len(m) != 1 {
				t.Fatalf("map %#v lacks key %#v", m, tc.key)
			}
		})
	}
}

// D4: embedded structs follow the encoding/json promotion rules.
func TestD4_EmbeddedStructs(t *testing.T) {
	type Inner struct {
		A int    `cbor:"a"`
		B string `cbor:"b"`
	}
	type inner struct {
		D int `cbor:"d"`
	}
	type Outer struct {
		Inner
		*inner
		C int `cbor:"c"`
	}
	enc := New(ModeCoreDeterministic)
	got, err := enc.Marshal(Outer{Inner: Inner{1, "x"}, inner: &inner{4}, C: 2})
	if err != nil {
		t.Fatal(err)
	}
	// {"a": 1, "b": "x", "c": 2, "d": 4}
	if want := "a4616101616261786163026164" + "04"; hex.EncodeToString(got) != want {
		t.Fatalf("Marshal = %x, want %s", got, want)
	}

	var o Outer
	if err := Unmarshal(got, &o); err == nil {
		t.Fatal("decoding into a nil embedded pointer to an unexported struct must fail")
	}

	// A nil embedded pointer omits its fields on encode.
	got, err = enc.Marshal(Outer{Inner: Inner{1, "x"}, C: 2})
	if err != nil {
		t.Fatal(err)
	}
	if want := "a3616101616261786163" + "02"; hex.EncodeToString(got) != want {
		t.Fatalf("Marshal(nil embedded) = %x, want %s", got, want)
	}

	type Exported struct{ D int }
	type WithPtr struct {
		*Exported
		C int `cbor:"c"`
	}
	var w WithPtr
	if err := Unmarshal(mustHex(t, "a2616404616302"), &w); err != nil { // {"d": 4, "c": 2}
		t.Fatal(err)
	}
	if w.Exported == nil || w.D != 4 || w.C != 2 {
		t.Fatalf("decoded %+v", w)
	}
}

func TestD4_EmbeddedConflicts(t *testing.T) {
	type X struct{ V int }
	type Y struct{ V int }
	type Tagged struct {
		V int `cbor:"v"`
	}
	// Same depth, both untagged: the field is dropped.
	type Tie struct {
		X
		Y
	}
	// Same depth, one tagged: the tagged field wins.
	type TaggedWins struct {
		X
		Tagged
	}
	// Shallower wins.
	type Shallow struct {
		X
		V string
	}
	enc := New(ModeCoreDeterministic)
	for name, tc := range map[string]struct {
		v    any
		want string
	}{
		"tie":         {Tie{X{1}, Y{2}}, "a0"},
		"tagged-wins": {TaggedWins{X{1}, Tagged{2}}, "a1617602"},
		"shallow":     {Shallow{X{1}, "s"}, "a161766173"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := enc.Marshal(tc.v)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("Marshal = %x, want %s", got, tc.want)
			}
		})
	}
}

// D4: a tag that only sets options keeps the default field name.
func TestD4_OptionOnlyTagKeepsName(t *testing.T) {
	type S struct {
		Name string `cbor:",omitempty"`
		Age  int    `cbor:",omitempty"`
	}
	got, err := New(ModeCoreDeterministic).Marshal(S{Name: "n", Age: 3})
	if err != nil {
		t.Fatal(err)
	}
	// {"age": 3, "name": "n"}
	if want := "a263616765" + "03" + "646e616d65616e"; hex.EncodeToString(got) != want {
		t.Fatalf("Marshal = %x, want %s", got, want)
	}
	var s S
	if err := Unmarshal(got, &s); err != nil || s.Name != "n" || s.Age != 3 {
		t.Fatalf("Unmarshal = %+v, %v", s, err)
	}
}

// D5: time and bignum helpers.
func TestD5_TimeTo(t *testing.T) {
	for _, sec := range []int64{-10, -1, 0, 1, math.MinInt64, math.MaxInt64} {
		v := cbor.TimeTo(time.Unix(sec, 0))
		back, err := cbor.AsTime(v)
		if err != nil || back.Unix() != sec {
			t.Fatalf("TimeTo(%d) round-trip = %v, %v", sec, back.Unix(), err)
		}
		if sec < 0 && v.TagInner().Kind != cbor.KindNegInt {
			t.Fatalf("TimeTo(%d) inner kind = %d, want NegInt", sec, v.TagInner().Kind)
		}
	}
	got, err := New(ModeCoreDeterministic).Encode(nil, cbor.TimeTo(time.Unix(-10, 0)))
	if err != nil || hex.EncodeToString(got) != "c129" {
		t.Fatalf("TimeTo(-10) = %x, %v; want c129", got, err)
	}
}

func TestD5_AsTimeRange(t *testing.T) {
	bad := []cbor.Value{
		cbor.MakeTag(1, cbor.Uint(math.MaxUint64)),
		cbor.MakeTag(1, cbor.NegInt(math.MaxUint64)),
		cbor.MakeTag(1, cbor.Float64(math.NaN())),
		cbor.MakeTag(1, cbor.Float64(math.Inf(1))),
		cbor.MakeTag(1, cbor.Float64(1e300)),
		cbor.MakeTag(1, cbor.Float32(float32(math.Inf(-1)))),
	}
	for _, v := range bad {
		if _, err := cbor.AsTime(v); !errors.Is(err, ErrTimeRange) {
			t.Errorf("AsTime(%v) err = %v, want ErrTimeRange", DiagnosticValue(v), err)
		}
	}
	// Large but valid float epochs keep sub-second precision.
	got, err := cbor.AsTime(cbor.MakeTag(1, cbor.Float64(-1.5)))
	if err != nil || !got.Equal(time.Unix(-2, 5e8)) {
		t.Fatalf("AsTime(1(-1.5)) = %v, %v", got, err)
	}
	got, err = cbor.AsTime(cbor.MakeTag(1, cbor.Float64(4e10+0.25)))
	if err != nil || got.Unix() != 4e10 || got.Nanosecond() != 25e7 {
		t.Fatalf("AsTime(1(4e10+0.25)) = %v, %v", got, err)
	}
}

func TestD5_BigIntToNil(t *testing.T) {
	if v := cbor.BigIntTo(nil); v.Kind != cbor.KindNull {
		t.Fatalf("BigIntTo(nil).Kind = %d, want Null", v.Kind)
	}
}

// D7: integers beyond int64 don't wrap.
func TestD7_IntegerRange(t *testing.T) {
	var v any
	if err := Unmarshal(mustHex(t, "3bffffffffffffffff"), &v); err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 64)) // -2^64
	if n, ok := v.(*big.Int); !ok || n.Cmp(want) != 0 {
		t.Fatalf("got %v (%T), want %v", v, v, want)
	}
	if err := Unmarshal(mustHex(t, "3b7fffffffffffffff"), &v); err != nil || v != int64(math.MinInt64) {
		t.Fatalf("got %v (%T), want MinInt64", v, v)
	}

	// Uint 2^64-1 must not match the field keyed -1.
	type S struct {
		N int `cbor:"-1"`
	}
	var s S
	if err := Unmarshal(mustHex(t, "a11bffffffffffffffff07"), &s); err != nil {
		t.Fatal(err)
	}
	if s.N != 0 {
		t.Fatalf("uint key 2^64-1 matched field -1: %+v", s)
	}
	// NegInt -2^64 must not match field 0.
	type Z struct {
		N int `cbor:"0"`
	}
	var z Z
	if err := Unmarshal(mustHex(t, "a13bffffffffffffffff07"), &z); err != nil {
		t.Fatal(err)
	}
	if z.N != 0 {
		t.Fatalf("negint key -2^64 matched field 0: %+v", z)
	}
}

// D8: the memory budget applies per DecodeSequence call.
func TestD8_SequenceBudgetPerCall(t *testing.T) {
	dec := NewDecoder(WithMemoryBudget(1024))
	seq := mustHex(t, "83010203"+"83040506")
	for i := range 100 {
		if _, err := dec.DecodeSequence(seq); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
}

// D9: a pool that hands out the wrong type doesn't panic Encode.
func TestD9_BufferPoolMistyped(t *testing.T) {
	for name, p := range map[string]*sync.Pool{
		"no-new":     {},
		"wrong-type": {New: func() any { return "nope" }},
	} {
		t.Run(name, func(t *testing.T) {
			enc := New(ModeCoreDeterministic, WithBufferPool(p))
			got, err := enc.Encode(nil, cbor.Uint(1))
			if err != nil || hex.EncodeToString(got) != "01" {
				t.Fatalf("Encode = %x, %v", got, err)
			}
		})
	}
}

// D3 (found by FuzzUnmarshalAnyNeverPanics): typed map[any]any targets
// and non-empty interface targets must not panic.
func TestD3_TypedInterfaceTargets(t *testing.T) {
	var m map[any]any
	if err := Unmarshal(mustHex(t, "a1410101"), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m[cbor.ByteKey("\x01")]; !ok {
		t.Fatalf("map %#v lacks ByteKey(\\x01)", m)
	}

	var s struct {
		S fmt.Stringer `cbor:"s"`
	}
	if err := Unmarshal(mustHex(t, "a1617301"), &s); err == nil { // {"s": 1}
		t.Fatal("uint64 into fmt.Stringer: want error")
	}
}
