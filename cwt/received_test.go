// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cwt"
)

func hexb(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var keep = cwt.DecodeOptions{KeepAsReceived: true}

// TestNonCanonicalNaNRejected: Encode would rewrite a NaN payload or
// sign bit to f97e00, so decoding rejects it by default, naming the
// claim. The quiet NaN f97e00 itself is fine.
func TestNonCanonicalNaNRejected(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		key      cwt.ClaimKey
	}{
		{"float32 payload", "a11864fa7fc00001", cwt.IntKey(100)},
		{"negative NaN", "a11864f9fe00", cwt.IntKey(100)},
		{"nested", "a1636e616e8201f97e01", cwt.TextKey("nan")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cwt.DecodeClaimsSet(hexb(t, tc.in))
			if !errors.Is(err, cwt.ErrNonCanonicalNaN) || !errors.Is(err, cwt.ErrMalformedClaims) {
				t.Fatalf("err = %v, want ErrNonCanonicalNaN and ErrMalformedClaims", err)
			}
			var ce *cwt.ClaimError
			if !errors.As(err, &ce) || ce.Key != tc.key {
				t.Fatalf("err = %v, want a *ClaimError for %v", err, tc.key)
			}
		})
	}

	in := hexb(t, "a11864f97e00")
	cs, err := cwt.DecodeClaimsSet(in)
	if err != nil {
		t.Fatalf("quiet NaN: %v", err)
	}
	if out, err := cs.Encode(); err != nil || !bytes.Equal(out, in) {
		t.Fatalf("quiet NaN Encode = %x, %v; want %x", out, err, in)
	}
}

// TestKeepAsReceived: with the option, those claims are kept byte for
// byte in ReceivedClaims and Encode writes them back unchanged, in
// deterministic key order; everything else decodes as usual.
func TestKeepAsReceived(t *testing.T) {
	// {bignum 1: null, 100: NaN payload, iss: "a"}, out of order.
	in := hexb(t, "a3"+"c24101f6"+"1864fa7fc00001"+"016161")
	cs, err := cwt.DecodeClaimsSetWith(in, keep)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Issuer != "a" {
		t.Errorf("Issuer = %q", cs.Issuer)
	}
	want := map[cwt.ClaimKey]string{
		{Raw: "\xc2\x41\x01"}: "f6",
		cwt.IntKey(100):       "fa7fc00001",
	}
	if len(cs.ReceivedClaims) != len(want) || len(cs.PrivateClaims) != 0 {
		t.Fatalf("ReceivedClaims = %x, PrivateClaims = %v", cs.ReceivedClaims, cs.PrivateClaims)
	}
	for k, v := range want {
		if hex.EncodeToString(cs.ReceivedClaims[k]) != v {
			t.Errorf("ReceivedClaims[%v] = %x, want %s", k, cs.ReceivedClaims[k], v)
		}
	}

	out, err := cs.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if wantOut := hexb(t, "a3"+"016161"+"1864fa7fc00001"+"c24101f6"); !bytes.Equal(out, wantOut) {
		t.Fatalf("Encode = %x, want %x", out, wantOut)
	}
	// Still protected without the option.
	if _, err := cwt.DecodeClaimsSet(out); !errors.Is(err, cwt.ErrNonCanonicalNaN) && !errors.Is(err, cwt.ErrAmbiguousClaimKey) {
		t.Fatalf("re-decode without KeepAsReceived err = %v", err)
	}
	// Cleaning up: drop the claims and the rest encodes normally.
	clear(cs.ReceivedClaims)
	if out, err := cs.Encode(); err != nil || !bytes.Equal(out, hexb(t, "a1016161")) {
		t.Fatalf("after cleanup Encode = %x, %v", out, err)
	}
}

func TestKeepAsReceivedExactBytes(t *testing.T) {
	for _, tc := range []struct{ name, in, key, val string }{
		{"non-shortest bignum key", "a1c2580101f6", "c2580101", "f6"},
		{"leading zeros", "a1c243000001f6", "c243000001", "f6"},
		{"half-float payload", "a11864f97e01", "", "f97e01"},
		{"self-describe prefix", "d9d9f7a11864f9fe00", "", "f9fe00"},
		{"indefinite map", "bf1864f97e01ff", "", "f97e01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := cwt.DecodeClaimsSetWith(hexb(t, tc.in), keep)
			if err != nil {
				t.Fatal(err)
			}
			k := cwt.IntKey(100)
			if tc.key != "" {
				k = cwt.ClaimKey{Raw: string(hexb(t, tc.key))}
			}
			if got := hex.EncodeToString(cs.ReceivedClaims[k]); got != tc.val {
				t.Fatalf("ReceivedClaims = %x, want %s under %v", cs.ReceivedClaims, tc.val, k)
			}
			out, err := cs.Encode()
			if err != nil {
				t.Fatal(err)
			}
			again, err := cwt.DecodeClaimsSetWith(out, keep)
			if err != nil || hex.EncodeToString(again.ReceivedClaims[k]) != tc.val {
				t.Fatalf("round trip: %x, %v", out, err)
			}
		})
	}
}

func TestKeepAsReceivedLimits(t *testing.T) {
	// A modeled claim is parsed and checked, never kept.
	if _, err := cwt.DecodeClaimsSetWith(hexb(t, "a1038201f97e01"), keep); !errors.Is(err, cwt.ErrNonCanonicalNaN) {
		t.Errorf("aud with NaN payload err = %v, want ErrNonCanonicalNaN", err)
	}
	// Duplicates under the deprecated option can't be matched to spans.
	opts := keep
	opts.AllowDuplicateClaims = true //nolint:staticcheck // the edge being tested
	if _, err := cwt.DecodeClaimsSetWith(hexb(t, "a218640118640f"), opts); !errors.Is(err, cwt.ErrMalformedClaims) {
		t.Errorf("duplicates err = %v, want ErrMalformedClaims", err)
	}

	// Encode checks bytes a caller put in ReceivedClaims.
	for name, cs := range map[string]*cwt.ClaimsSet{
		"value not one item": {ReceivedClaims: map[cwt.ClaimKey]corecbor.RawMessage{cwt.IntKey(100): {0x01, 0x02}}},
		"truncated value":    {ReceivedClaims: map[cwt.ClaimKey]corecbor.RawMessage{cwt.IntKey(100): {0xfa, 0x7f}}},
		"bad Raw key":        {ReceivedClaims: map[cwt.ClaimKey]corecbor.RawMessage{{Raw: "\xc2"}: {0xf6}}},
		"conflict": {
			PrivateClaims:  map[cwt.ClaimKey]corecbor.Value{cwt.IntKey(100): corecbor.Uint(1)},
			ReceivedClaims: map[cwt.ClaimKey]corecbor.RawMessage{cwt.IntKey(100): {0xf9, 0x7e, 0x01}},
		},
	} {
		if _, err := cs.Encode(); !errors.Is(err, cwt.ErrMalformedClaims) {
			t.Errorf("%s: Encode err = %v, want ErrMalformedClaims", name, err)
		}
	}
}

// TestEncodeNonFinite: ±Inf and the quiet NaN decode and now also
// encode; they are exact in Core Deterministic encoding.
func TestEncodeNonFinite(t *testing.T) {
	for _, h := range []string{"a11864f97c00", "a11864f9fc00", "a11864f97e00"} {
		in := hexb(t, h)
		cs, err := cwt.DecodeClaimsSet(in)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if out, err := cs.Encode(); err != nil || !bytes.Equal(out, in) {
			t.Fatalf("%s: Encode = %x, %v", h, out, err)
		}
	}
}

// TestEncodeRejectsNaNPayload: Encode doesn't rewrite a NaN payload a
// caller set; it reports it.
func TestEncodeRejectsNaNPayload(t *testing.T) {
	cs := &cwt.ClaimsSet{PrivateClaims: map[cwt.ClaimKey]corecbor.Value{
		cwt.IntKey(100): corecbor.MakeArrayFromSlice([]corecbor.Value{{Kind: corecbor.KindFloat32, Num: 0x7fc00001}}),
	}}
	if _, err := cs.Encode(); !errors.Is(err, cwt.ErrNonCanonicalNaN) {
		t.Fatalf("Encode err = %v, want ErrNonCanonicalNaN", err)
	}
}
