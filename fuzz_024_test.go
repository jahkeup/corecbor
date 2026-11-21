// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/rfc8949"
)

// keyTable lists map-key encodings with their data-model equivalence
// class (RFC 8949 §5.6.1 + erratum 8589). Encodings are pairwise
// distinct, so encoded identity is "same index".
var keyTable = []struct {
	hex   string
	class int
}{
	{"01", 0}, {"1801", 0}, {"190001", 0}, // 1
	{"f93c00", 1}, {"fa3f800000", 1}, {"fb3ff0000000000000", 1}, // 1.0
	{"f97e00", 2}, {"fa7fc00000", 2}, // quiet NaN, same zero-extended significand
	{"f97e01", 3},                // NaN with payload
	{"f9fe00", 4},                // negative NaN
	{"f90000", 5}, {"f98000", 5}, // +0, -0
	{"6161", 6}, {"7f6161ff", 6}, {"780161", 6}, // "a"
	{"4161", 7},                // h'61'
	{"8101", 8}, {"811801", 8}, // [1]
	{"a0", 9},                              // {}
	{"c101", 10},                           // 1(1)
	{"f6", 11},                             // null
	{"20", 12},                             // -1
	{"f4", 13},                             // false
	{"a201010202", 14}, {"a202020101", 14}, // {1:1, 2:2} in either order
}

type keyPolicy int

const (
	policyLastWins keyPolicy = iota
	policyReject
	policyKeep
)

// FuzzMapKeyIdentity: for each key identity and duplicate policy, a
// decoded map agrees with a reference model, for definite maps on both
// sides of the 16-entry hashing threshold and for indefinite maps.
func FuzzMapKeyIdentity(f *testing.F) {
	f.Add([]byte{0, 1, 2}, false)
	f.Add([]byte{3, 4, 5, 6, 7, 8, 9, 10, 11}, false)
	f.Add([]byte{12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 1, 2, 3, 4}, true)
	f.Fuzz(func(t *testing.T, picks []byte, indefinite bool) {
		if len(picks) == 0 || len(picks) > 40 {
			return
		}
		idx := make([]int, len(picks))
		var src []byte
		if indefinite {
			src = append(src, 0xbf)
		} else {
			src = append(src, 0xb8, byte(len(picks)))
		}
		for i, p := range picks {
			idx[i] = int(p) % len(keyTable)
			k, _ := hex.DecodeString(keyTable[idx[i]].hex)
			src = append(src, k...)
			src = append(src, 0x18, byte(i)) // value: entry position
		}
		if indefinite {
			src = append(src, 0xff)
		}

		for _, id := range []KeyIdentity{KeyIdentityValue, KeyIdentityEncoded} {
			same := func(a, b int) bool {
				if id == KeyIdentityEncoded {
					return a == b
				}
				return keyTable[a].class == keyTable[b].class
			}
			for _, pol := range []keyPolicy{policyLastWins, policyReject, policyKeep} {
				opts := []DecoderOption{WithMapKeyIdentity(id)}
				switch pol {
				case policyReject:
					opts = append(opts, RejectDuplicateMapKeys())
				case policyKeep:
					opts = append(opts, KeepDuplicateMapKeys())
				}
				v, err := NewDecoder(opts...).Decode(src)

				// Reference model: positions of first occurrences, and
				// the last value written for each.
				var firsts []int
				lastVal := map[int]int{}
				dup := false
			next:
				for i := range idx {
					for _, fi := range firsts {
						if same(idx[fi], idx[i]) {
							dup = true
							lastVal[fi] = i
							continue next
						}
					}
					firsts = append(firsts, i)
					lastVal[i] = i
				}

				if pol == policyReject {
					if dup != errors.Is(err, ErrDuplicateMapKey) {
						t.Fatalf("id=%d reject: dup=%v err=%v src=%x", id, dup, err, src)
					}
					if dup {
						continue
					}
				}
				if err != nil {
					t.Fatalf("id=%d pol=%d: %v src=%x", id, pol, err, src)
				}
				var want []int // expected entry values, in order
				if pol == policyKeep {
					for i := range idx {
						want = append(want, i)
					}
				} else {
					for _, fi := range firsts {
						want = append(want, lastVal[fi])
					}
				}
				if len(v.Pairs) != len(want) {
					t.Fatalf("id=%d pol=%d: %d pairs, want %d (src=%x)", id, pol, len(v.Pairs), len(want), src)
				}
				for i, w := range want {
					if got := int(v.Pairs[i].Value.Num); got != w {
						t.Fatalf("id=%d pol=%d: entry %d value %d, want %d (src=%x)", id, pol, i, got, w, src)
					}
				}
			}
		}
	})
}

// FuzzEncodePassesCheckingDecoder: whatever the encoder emits in a
// deterministic mode passes the matching checking decoder.
// CoreDeterministic → RequireDeterministic; PreferredPlus →
// RequirePreferredPlus; Canonical → preferred serialization (its
// length-first order isn't bytewise-lex). CTAP2 forces float64, so only
// its non-float shape is checked indirectly via Canonical.
func FuzzEncodePassesCheckingDecoder(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}
	f.Add(mustHexB("c24a00000000000000000001")) // bignum with leading zeros
	f.Add(mustHexB("a2616201616102"))
	f.Add(mustHexB("f97e01"))
	dec := NewDecoder(WithoutInternalArena())
	core := New(ModeCoreDeterministic, AllowNonFiniteFloats(), AllowInvalidUTF8())
	pp := New(ModePreferredPlus, AllowNonFiniteFloats(), AllowInvalidUTF8())
	canon := New(ModeCanonical, AllowNonFiniteFloats(), AllowInvalidUTF8())
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := dec.Decode(data)
		if err != nil {
			return
		}
		if out, err := core.Encode(nil, v); err == nil {
			if _, err := NewDecoder(RequireDeterministic()).Decode(out); err != nil {
				t.Fatalf("CoreDeterministic output %x fails RequireDeterministic: %v (input %x)", out, err, data)
			}
		}
		if out, err := pp.Encode(nil, v); err == nil {
			if _, err := NewDecoder(RequirePreferredPlus()).Decode(out); err != nil {
				t.Fatalf("PreferredPlus output %x fails RequirePreferredPlus: %v (input %x)", out, err, data)
			}
		}
		if out, err := canon.Encode(nil, v); err == nil {
			if _, _, err := rfc8949.Decode(out, rfc8949.DecodeOpts{RequirePreferred: true}); err != nil {
				t.Fatalf("Canonical output %x not preferred: %v (input %x)", out, err, data)
			}
		}
	})
}
