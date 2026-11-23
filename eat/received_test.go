// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/eat"
)

func hexb(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNaNPayloadRejected: re-encoding would replace a NaN payload with
// f97e00, so decoding rejects it by default, with cwt's sentinel.
func TestNaNPayloadRejected(t *testing.T) {
	for name, h := range map[string]string{
		"unmodeled claim": "a11864fa7fc00001",
		"in a submodule":  "a1" + "19010a" + "a1" + "6161" + "a11864f97e01",
		"location":        "a1" + "190108" + "a2" + "01fa7fc00001" + "02f90000",
	} {
		_, err := eat.DecodeClaims(hexb(t, h))
		if !errors.Is(err, cwt.ErrNonCanonicalNaN) || !errors.Is(err, eat.ErrMalformedEAT) {
			t.Errorf("%s: err = %v, want cwt.ErrNonCanonicalNaN and ErrMalformedEAT", name, err)
		}
	}
	// A modeled claim stays checked with the option.
	if _, err := eat.DecodeClaims(hexb(t, "a1190108a201fa7fc0000102f90000"), eat.WithKeepAsReceived()); !errors.Is(err, cwt.ErrNonCanonicalNaN) {
		t.Errorf("location with WithKeepAsReceived: err = %v, want cwt.ErrNonCanonicalNaN", err)
	}
}

// TestWithKeepAsReceived: kept claims land in ReceivedClaims, at the top
// level and in inline submodules, and Encode writes them back exactly.
func TestWithKeepAsReceived(t *testing.T) {
	// Deterministic order, so Encode must reproduce it byte for byte:
	// {nonce: h'0102030405060708', 100: NaN payload, bignum 10: 1,
	//  submods: {"a": {100: -NaN, bignum 1: null}}}
	in := hexb(t, "a4"+
		"0a480102030405060708"+
		"1864f97e01"+
		"19010a"+"a1"+"6161"+"a2"+"1864f9fe00"+"c24101f6"+
		"c2410a01")
	for _, opts := range [][]eat.Option{
		{eat.WithKeepAsReceived()},
	} {
		c, err := eat.DecodeClaims(in, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Nonce) != 1 || !bytes.Equal(c.Nonce[0], hexb(t, "0102030405060708")) {
			t.Errorf("Nonce = %x", c.Nonce)
		}
		checkReceived(t, "top", c.ReceivedClaims, map[cwt.ClaimKey]string{
			cwt.IntKey(100):       "f97e01",
			{Raw: "\xc2\x41\x0a"}: "01",
		})
		sub := c.Submods["a"].Claims
		if sub == nil {
			t.Fatalf("Submods = %+v", c.Submods)
		}
		checkReceived(t, "submod", sub.ReceivedClaims, map[cwt.ClaimKey]string{
			cwt.IntKey(100):       "f9fe00",
			{Raw: "\xc2\x41\x01"}: "f6",
		})

		out, err := c.Encode(opts...)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("Encode =\n%x\nwant\n%x", out, in)
		}
		if _, err := eat.DecodeClaims(out); err == nil {
			t.Fatal("re-decode without WithKeepAsReceived succeeded")
		}
	}
}

// TestWithKeepAsReceivedLegacy: the draft-era numbering (submods 268)
// keeps claims in submodules the same way.
func TestWithKeepAsReceivedLegacy(t *testing.T) {
	in := hexb(t, "a1"+"19010c"+"a1"+"6161"+"a1"+"1864f97e01")
	opts := []eat.Option{eat.WithKeepAsReceived(), eat.WithLegacyDraftClaimKeys()} //nolint:staticcheck // legacy numbering
	c, err := eat.DecodeClaims(in, opts...)
	if err != nil {
		t.Fatal(err)
	}
	checkReceived(t, "submod", c.Submods["a"].Claims.ReceivedClaims, map[cwt.ClaimKey]string{cwt.IntKey(100): "f97e01"})
	if out, err := c.Encode(opts...); err != nil || !bytes.Equal(out, in) {
		t.Fatalf("Encode = %x, %v; want %x", out, err, in)
	}
}

// TestEncodeRejectsNaNPayload: Encode reports a NaN payload in a typed
// field rather than rewrite it.
func TestEncodeRejectsNaNPayload(t *testing.T) {
	c := &eat.Claims{Location: &eat.Location{Latitude: math.Float64frombits(0x7ff8000000000001)}}
	if _, err := c.Encode(); !errors.Is(err, cwt.ErrNonCanonicalNaN) {
		t.Fatalf("Encode err = %v, want cwt.ErrNonCanonicalNaN", err)
	}
	// Go's math.NaN() is 0x7ff8000000000001, a payload: also an error.
	c.Location.Latitude = math.NaN()
	if _, err := c.Encode(); !errors.Is(err, cwt.ErrNonCanonicalNaN) {
		t.Fatalf("math.NaN(): err = %v, want cwt.ErrNonCanonicalNaN", err)
	}
	c.Location.Latitude = math.Float64frombits(0x7ff8000000000000) // f97e00: exact
	if _, err := c.Encode(); err != nil {
		t.Fatalf("quiet NaN: %v", err)
	}
}

func checkReceived(t *testing.T, where string, got map[cwt.ClaimKey]corecbor.RawMessage, want map[cwt.ClaimKey]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: ReceivedClaims = %x, want %v", where, got, want)
	}
	for k, v := range want {
		if hex.EncodeToString(got[k]) != v {
			t.Errorf("%s: ReceivedClaims[%v] = %x, want %s", where, k, got[k], v)
		}
	}
}
