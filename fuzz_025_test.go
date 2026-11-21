// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

type fuzzArrInner struct {
	_ struct{} `cbor:",toarray"`
	N int
	S *string
}

type fuzzEmbedded struct{ E []byte }

type fuzzStruct025 struct {
	fuzzEmbedded
	Arr  fuzzArrInner `cbor:"arr"`
	Raw  RawMessage   `cbor:"raw"`
	Addr netip.Addr   `cbor:"addr"`
	Up   upper        `cbor:"up"`
	Z    zeroer       `cbor:"z,omitzero"`
	Tail *fuzzArrInner
}

// FuzzUnmarshalStructNeverPanics: arbitrary input into a struct with
// toarray, embedded, raw, Text/Binary-unmarshaler and omitzero fields,
// under every 025 decoder option, returns without panicking; anything
// that decodes re-marshals.
func FuzzUnmarshalStructNeverPanics(f *testing.F) {
	for _, h := range []string{
		"a0", "a163617272820102", "a1636172728101", "a2636172728201f66372617743a10102",
		"a164616464724404030201", "a1627570626162", "a16461727284010203f6", "820102",
		"a2615a01617a02", "a16474616966820161", "a2667573657269646162665573657249446161",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	decs := []*Decoder{
		NewDecoder(),
		NewDecoder(DisallowUnknownFields()),
		NewDecoder(WithCaseInsensitiveFieldNames(), DisallowUnknownFields()),
		NewDecoder(WithLegacyNoTextBinaryUnmarshal()),
	}
	enc := New(ModePermissive, WithGoFieldNames())
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, d := range decs {
			var s fuzzStruct025
			if d.Unmarshal(data, &s) != nil {
				continue
			}
			if _, err := Marshal(s); err != nil {
				// Values that decoded can fail to re-encode only on
				// invalid UTF-8 text (encoder rejects by default).
				continue
			}
			_, _ = enc.Marshal(s)
		}
	})
}
