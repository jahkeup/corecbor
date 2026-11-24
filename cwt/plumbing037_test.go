// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

// TestMACOptionsPlumbing037: callers with deployed short HMAC keys can
// pass cose.InsecureAllowShortMACKeys through every cwt MAC path; the
// RFC 9053 §3.1 length check stays the default.
func TestMACOptionsPlumbing037(t *testing.T) {
	short := bytes.Repeat([]byte{0x11}, 16) // HMAC 256/256 wants 32
	claims := &cwt.ClaimsSet{Issuer: "i", Expiration: time.Now().Add(time.Hour)}
	if _, err := cwt.MAC(claims, short, cose.AlgHMAC256); !errors.Is(err, cose.ErrInvalidKey) {
		t.Fatalf("MAC with a short key: %v, want cose.ErrInvalidKey", err)
	}
	allow := cose.InsecureAllowShortMACKeys()
	tok, err := cwt.MAC(claims, short, cose.AlgHMAC256, allow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cwt.VerifyMAC(tok, short, cose.AlgHMAC256); !errors.Is(err, cose.ErrInvalidKey) {
		t.Errorf("VerifyMAC default: %v, want cose.ErrInvalidKey", err)
	}
	if _, err := cwt.VerifyMAC(tok, short, cose.AlgHMAC256, allow); err != nil {
		t.Errorf("VerifyMAC with the opt-in: %v", err)
	}
	ctx := context.Background()
	if _, err := cwt.VerifyMACToken(ctx, tok, short, cwt.VerifyOptions{}); !errors.Is(err, cose.ErrInvalidKey) {
		t.Errorf("VerifyMACToken default: %v, want cose.ErrInvalidKey", err)
	}
	if _, err := cwt.VerifyMACToken(ctx, tok, short, cwt.VerifyOptions{MACOptions: []cose.MACOption{allow}}); err != nil {
		t.Errorf("VerifyMACToken with the opt-in: %v", err)
	}
}

// TestDecodeLimitsPlumbing037: the envelope is bounded by default and a
// caller can raise the bound for large tokens.
func TestDecodeLimitsPlumbing037(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	claims := &cwt.ClaimsSet{
		Issuer:        "i",
		Expiration:    time.Now().Add(time.Hour),
		PrivateClaims: map[cwt.ClaimKey]corecbor.Value{cwt.IntKey(-70000): corecbor.Bytes(make([]byte, 2<<20))},
	}
	tok, err := cwt.MAC(claims, key, cose.AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := cwt.VerifyMACToken(ctx, tok, key, cwt.VerifyOptions{}); err == nil {
		t.Fatal("a 2 MiB token passed the default 1 MiB budget")
	}
	raised := cwt.VerifyOptions{DecodeLimits: cose.DecodeLimits{MemoryBudget: 8 << 20}}
	if _, err := cwt.VerifyMACToken(ctx, tok, key, raised); err != nil {
		t.Fatalf("with an 8 MiB budget: %v", err)
	}
}
