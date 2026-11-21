// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/rfc8949"
	"github.com/jahkeup/corecbor/wire"
)

func addRawSeeds(f *testing.F) {
	for _, tc := range rfc8949Vectors {
		b, _ := hex.DecodeString(tc.hexEncoded)
		f.Add(b)
	}
	for _, h := range []string{
		"a2616201616102", "9f0102ff", "bf6161016162ff", "5f41014102ff",
		"d9d9f7820102", "81d9d9f701", "1800", "ff", "1f", "f818", "8282" + "0000",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
}

// errClass names the sentinel an error wraps, for comparing error
// classes between decode paths.
func errClass(err error) string {
	if err == nil {
		return ""
	}
	for _, s := range []error{
		ErrTruncated, ErrUnexpectedBreak, ErrReservedAI, ErrNonShortest,
		ErrMaxNestingDepth, ErrMaxArrayLength, ErrMaxByteStringLength,
	} {
		if errors.Is(err, s) {
			return s.Error()
		}
	}
	return "other: " + err.Error()
}

// FuzzRawSpanRoundTrip: for any input, Cursor.Skip agrees with Decode
// on success, length and error class; for accepted input, DecodeRaw
// returns all of src, and the Raw spans of a top-level container's
// items concatenate to its body.
func FuzzRawSpanRoundTrip(f *testing.F) {
	addRawSeeds(f)
	dec := NewDecoder(WithoutInternalArena())
	f.Fuzz(func(t *testing.T, data []byte) {
		_, n, decErr := rfc8949.Decode(data, rfc8949.DecodeOpts{})
		skipped, skipErr := rfc8949.NewCursor(data, rfc8949.DecodeOpts{}).Skip()
		if errClass(decErr) != errClass(skipErr) {
			t.Fatalf("Decode err %v, Skip err %v", decErr, skipErr)
		}
		if decErr != nil {
			return
		}
		if skipped != n {
			t.Fatalf("Decode consumed %d, Skip %d", n, skipped)
		}
		item := data[:n]
		_, raw, err := dec.DecodeRaw(item)
		if err != nil || !bytes.Equal(raw, item) {
			t.Fatalf("DecodeRaw = %x, %v; want %x", raw, err, item)
		}

		body := stripSelfDescribe(item)
		h := wire.ParseHead(body)
		if h.Major != wire.MajorArray && h.Major != wire.MajorMap {
			return
		}
		c := dec.Cursor(body)
		if h.Major == wire.MajorArray {
			_, err = c.EnterArray()
		} else {
			_, err = c.EnterMap()
		}
		if err != nil {
			t.Fatal(err)
		}
		var cat []byte
		for !c.AtEnd() && !c.AtBreak() {
			span, err := c.Raw()
			if err != nil {
				t.Fatalf("Raw: %v", err)
			}
			got, err := c.RawBytes()
			if err != nil || !bytes.Equal(got, span) {
				t.Fatalf("RawBytes = %x, %v; Raw %x", got, err, span)
			}
			cat = append(cat, span...)
		}
		end := len(body)
		if h.AI == wire.AIIndefinite {
			end-- // break code
		}
		if want := body[h.N:end]; !bytes.Equal(cat, want) {
			t.Fatalf("item spans %x, body %x", cat, want)
		}
	})
}

// FuzzDecodePrefixMatchesSequence: repeated DecodePrefix yields the
// same items (and failure) as DecodeSequence.
func FuzzDecodePrefixMatchesSequence(f *testing.F) {
	addRawSeeds(f)
	dec := NewDecoder(WithoutInternalArena())
	f.Fuzz(func(t *testing.T, data []byte) {
		seq, seqErr := dec.DecodeSequence(data)
		var items []string
		rest := data
		var prefixErr error
		for len(rest) > 0 {
			var v Value
			v, rest, prefixErr = dec.DecodePrefix(rest)
			if prefixErr != nil {
				break
			}
			items = append(items, DiagnosticValue(v))
		}
		if errClass(seqErr) != errClass(prefixErr) {
			t.Fatalf("DecodeSequence err %v, DecodePrefix err %v", seqErr, prefixErr)
		}
		if seqErr != nil {
			return
		}
		if len(items) != len(seq) {
			t.Fatalf("DecodePrefix %d items, DecodeSequence %d", len(items), len(seq))
		}
		for i := range seq {
			if items[i] != DiagnosticValue(seq[i]) {
				t.Fatalf("item %d: %s vs %s", i, items[i], DiagnosticValue(seq[i]))
			}
		}
	})
}

// FuzzUnmarshalRawMessage: {"r": <item>} into a RawMessage field keeps
// the item's bytes, and Permissive Marshal reproduces the input.
func FuzzUnmarshalRawMessage(f *testing.F) {
	addRawSeeds(f)
	enc := New(ModePermissive, AllowNonFiniteFloats(), AllowInvalidUTF8())
	f.Fuzz(func(t *testing.T, data []byte) {
		_, n, err := rfc8949.Decode(data, rfc8949.DecodeOpts{})
		if err != nil {
			return
		}
		item := data[:n]
		in := append([]byte{0xa1, 0x61, 'r'}, item...)
		if _, _, err := rfc8949.Decode(in, rfc8949.DecodeOpts{}); err != nil {
			return // wrapping can exceed the nesting limit
		}
		var s struct {
			R RawMessage `cbor:"r"`
		}
		if err := Unmarshal(in, &s); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !bytes.Equal(s.R, item) {
			t.Fatalf("RawMessage = %x, want %x", []byte(s.R), item)
		}
		out, err := enc.Marshal(s)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("Marshal = %x, want %x", out, in)
		}
	})
}
