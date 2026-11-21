// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

type fuzzInner struct {
	A int    `cbor:"a"`
	B string `cbor:"b,omitempty"`
}

type fuzzInnerPtr struct {
	P []byte `cbor:"p"`
}

// fuzzTarget exercises the reflection paths touched by proposal 021:
// cbor.Value and any fields, embedded (value and pointer) structs,
// integer keys including negative ones, tags, time and bignums.
type fuzzTarget struct {
	fuzzInner
	*fuzzInnerPtr
	V   cbor.Value        `cbor:"v"`
	X   any               `cbor:"x"`
	N   int8              `cbor:"-1"`
	U   uint16            `cbor:"1"`
	M   map[string]any    `cbor:"m"`
	MA  map[any]any       `cbor:"ma"`
	S   []fuzzInner       `cbor:"s"`
	T   time.Time         `cbor:"t"`
	Tag uint64            `cbor:"tg,tag=42"`
	Arr [2]float32        `cbor:"arr"`
	Ptr *map[int64]string `cbor:"ptr"`
}

func addUnmarshalSeeds(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}
	for _, h := range []string{
		"a1410101",                     // {h'01': 1}
		"a182010201",                   // {[1, 2]: 1}
		"a1c10101",                     // {1(1): 1}
		"3bffffffffffffffff",           // -2^64
		"a11bffffffffffffffff07",       // {2^64-1: 7}
		"a2616101616262",               // {"a": 1, "b": "b"}
		"a16170a1616101",               // {"p": {"a": 1}}
		"a16174c13a7fffffff",           // {"t": 1(-2^31)}
		"a16174c1fb7ff8000000000000",   // {"t": 1(NaN)}
		"a1627467d82a01",               // {"tg": 42(1)}
		"a2617682010261788201a1410102", // {"v": [1, 2], "x": [1, {h'01': 2}]}
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
}

// FuzzUnmarshalAnyNeverPanics: arbitrary input into any, map[any]any
// and a struct with every field shape must return (possibly an error)
// without panicking.
func FuzzUnmarshalAnyNeverPanics(f *testing.F) {
	addUnmarshalSeeds(f)
	dec := NewDecoder()
	f.Fuzz(func(t *testing.T, data []byte) {
		var a any
		_ = dec.Unmarshal(data, &a)
		var m map[any]any
		_ = dec.Unmarshal(data, &m)
		var s fuzzTarget
		_ = dec.Unmarshal(data, &s)
	})
}

// FuzzUnmarshalConcurrent: package-level Unmarshal of the same input
// from several goroutines must agree and must not race (run with -race).
func FuzzUnmarshalConcurrent(f *testing.F) {
	addUnmarshalSeeds(f)
	enc := NewShared(ModeCoreDeterministic, AllowNonFiniteFloats(), AllowInvalidUTF8())
	f.Fuzz(func(t *testing.T, data []byte) {
		var ref cbor.Value
		if Unmarshal(data, &ref) != nil {
			return
		}
		want, err := enc.Encode(nil, ref)
		if err != nil {
			return
		}
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				var v cbor.Value
				if err := Unmarshal(data, &v); err != nil {
					t.Errorf("concurrent Unmarshal: %v", err)
					return
				}
				got, err := enc.Encode(nil, v)
				if err != nil || string(got) != string(want) {
					t.Errorf("concurrent Unmarshal = %x, %v; want %x", got, err, want)
				}
			})
		}
		wg.Wait()
		// ref must be unaffected by the decodes above.
		if got, _ := enc.Encode(nil, ref); string(got) != string(want) {
			t.Errorf("first result changed after later Unmarshal calls: %x, want %x", got, want)
		}
	})
}
