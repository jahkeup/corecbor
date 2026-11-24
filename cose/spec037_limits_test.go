// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"strings"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
)

// Proposal 037 S8: the Unmarshal* functions bound untrusted input by
// default (RecommendedDecodeLimits), signature and recipient counts are
// capped, and InsecureUnboundedDecodeLimits opts out.
func TestSpec037DecodeLimits(t *testing.T) {
	bigKid := hx(t, "84"+"40"+"a1"+"04"+"5a00100000"+strings.Repeat("00", 1<<20)+"40"+"40")
	if _, err := UnmarshalSign1(bigKid); !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("1 MiB kid by default: err = %v, want ErrMemoryBudgetExceeded", err)
	}
	if _, err := UnmarshalSign1With(bigKid, DecodeLimits{}); !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("1 MiB kid, DecodeLimits{}: err = %v, want ErrMemoryBudgetExceeded", err)
	}
	if _, err := UnmarshalSign1With(bigKid, InsecureUnboundedDecodeLimits); err != nil {
		t.Fatalf("1 MiB kid, unbounded: %v", err)
	}
	if _, err := UnmarshalSign1With(bigKid, DecodeLimits{MemoryBudget: 4 << 20}); err != nil {
		t.Fatalf("1 MiB kid, 4 MiB budget: %v", err)
	}

	deep := hx(t, "84"+"40"+"a1"+"01"+strings.Repeat("81", 20)+"00"+"40"+"40")
	if _, err := UnmarshalSign1(deep); !errors.Is(err, corecbor.ErrMaxNestingDepth) {
		t.Fatalf("depth 22 by default: err = %v, want ErrMaxNestingDepth", err)
	}
	if _, err := UnmarshalSign1With(deep, InsecureUnboundedDecodeLimits); err != nil {
		t.Fatalf("depth 22, unbounded: %v", err)
	}

	sig := "83" + "40" + "a0" + "40"
	signWith := func(n int) []byte {
		return hx(t, "d862"+"84"+"40"+"a0"+"40"+arrayHead(n)+strings.Repeat(sig, n))
	}
	if _, err := UnmarshalSign(signWith(32)); err != nil {
		t.Fatalf("32 signatures: %v", err)
	}
	if _, err := UnmarshalSign(signWith(33)); !errors.Is(err, ErrMalformed) || !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("33 signatures: err = %v, want ErrMalformed and ErrLimitExceeded", err)
	}
	if _, err := UnmarshalSignWith(signWith(33), DecodeLimits{MaxSignatures: 64}); err != nil {
		t.Fatalf("33 signatures, MaxSignatures 64: %v", err)
	}
	if _, err := UnmarshalSignWith(signWith(33), InsecureUnboundedDecodeLimits); err != nil {
		t.Fatalf("33 signatures, unbounded: %v", err)
	}

	rcpt := "83" + "40" + "a0" + "40"
	encWith := func(n int) []byte {
		return hx(t, "d860"+"84"+"40"+"a0"+"40"+arrayHead(n)+strings.Repeat(rcpt, n))
	}
	macWith := func(n int) []byte {
		return hx(t, "d861"+"85"+"40"+"a0"+"40"+"40"+arrayHead(n)+strings.Repeat(rcpt, n))
	}
	if _, err := UnmarshalEncrypt(encWith(64)); err != nil {
		t.Fatalf("64 recipients: %v", err)
	}
	if _, err := UnmarshalEncrypt(encWith(65)); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("65 recipients: err = %v, want ErrLimitExceeded", err)
	}
	if _, err := UnmarshalMac(macWith(65)); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("65 MAC recipients: err = %v, want ErrLimitExceeded", err)
	}
	if _, err := UnmarshalEncryptWith(encWith(65), DecodeLimits{MaxRecipients: -1}); err != nil {
		t.Fatalf("65 recipients, MaxRecipients -1: %v", err)
	}
}

func arrayHead(n int) string {
	switch {
	case n < 24:
		return string("0123456789abcdef"[8+n/16]) + string("0123456789abcdef"[n%16])
	case n < 256:
		return "98" + string("0123456789abcdef"[n/16]) + string("0123456789abcdef"[n%16])
	default:
		panic("arrayHead: n too large")
	}
}
