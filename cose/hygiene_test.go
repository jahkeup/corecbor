// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
)

// Proposal 027 Phase 3: H9 header typing, H10 concurrency, H13 error
// chains, decode limits.

func TestSetChecked(t *testing.T) {
	ok := []struct {
		label, value any
	}{
		{1, AlgES256},
		{int64(1), int64(-7)},
		{4, []byte("kid")},
		{"text", "v"},
		{3, uint64(1)},
		{16, true},
		{99, nil},
		{2, []any{int64(99), "x"}},
		{5, corecbor.Bytes([]byte{1})},
	}
	for _, tc := range ok {
		var h Headers
		if err := h.SetChecked(tc.label, tc.value); err != nil {
			t.Errorf("SetChecked(%v, %#v): %v", tc.label, tc.value, err)
		}
		if _, err := h.encodeProtected(); err != nil {
			t.Errorf("encode after SetChecked(%v, %#v): %v", tc.label, tc.value, err)
		}
	}

	var h Headers
	h.SetAlgorithm(AlgEdDSA)
	if err := h.SetChecked(4, struct{}{}); !errors.Is(err, ErrUnsupportedHeader) {
		t.Fatalf("struct value: err = %v, want ErrUnsupportedHeader", err)
	}
	if err := h.SetChecked(1.5, int64(1)); !errors.Is(err, ErrUnsupportedHeader) {
		t.Fatalf("float label: err = %v, want ErrUnsupportedHeader", err)
	}
	if h.Get(4) != nil || len(h.params) != 1 {
		t.Fatalf("headers changed by a failed SetChecked: %v", h.params)
	}
}

func TestSetTyping(t *testing.T) {
	var h Headers
	h.Set(1, AlgES256)
	h.Set(4, []byte("kid"))
	got, err := h.encodeProtected()
	if err != nil {
		t.Fatal(err)
	}
	// {1: -7, 4: h'6b6964'}
	if want := hx(t, "a2"+"0126"+"04436b6964"); !bytes.Equal(got, want) {
		t.Fatalf("encoded %x, want %x", got, want)
	}
	// int and int64 labels are the same label.
	if h.Get(int64(4)) == nil || h.Get(4) == nil {
		t.Fatal("Get by int / int64 label")
	}

	// An unencodable value set with Set surfaces at Marshal.
	msg := &Sign1{Payload: []byte("p")}
	msg.Unprotected.Set(4, struct{}{})
	if _, err := MarshalSign1(msg); !errors.Is(err, ErrUnsupportedHeader) {
		t.Fatalf("MarshalSign1: err = %v, want ErrUnsupportedHeader", err)
	}
	msg = &Sign1{Payload: []byte("p")}
	msg.Protected.Set(4, struct{}{})
	if _, err := MarshalSign1(msg); !errors.Is(err, ErrUnsupportedHeader) {
		t.Fatalf("MarshalSign1 (protected): err = %v, want ErrUnsupportedHeader", err)
	}
}

func TestDecodedLargeUintRoundTrips(t *testing.T) {
	// protected {99: 2^64-1}: v0.2.2 read it as int64(-1).
	prot := hx(t, "a118631bffffffffffffffff")
	h, err := decodeProtected(prot, DecodeLimits{})
	if err != nil {
		t.Fatal(err)
	}
	local := Headers{params: h.params}
	got, err := local.encodeProtected()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, prot) {
		t.Fatalf("re-encoded %x, want %x", got, prot)
	}
}

func TestHeadersCopyIndependent(t *testing.T) {
	prot := hx(t, "a10127") // {1: -8}
	h1, err := decodeProtected(prot, DecodeLimits{})
	if err != nil {
		t.Fatal(err)
	}
	h2 := *h1
	h2.Set(4, []byte("kid"))
	if h1.Get(4) != nil {
		t.Fatal("Set on a copy changed the original's parameters")
	}
	if !bytes.Equal(h1.Raw(), prot) {
		t.Fatal("Set on a copy changed the original's Raw()")
	}
	if got, _ := h1.encodeProtected(); !bytes.Equal(got, prot) {
		t.Fatalf("original encodes %x, want %x", got, prot)
	}
	if h2.Raw() != nil || h2.Get(4) == nil {
		t.Fatal("copy should carry the new label and no raw bytes")
	}
}

// TestConcurrentSignVerify: one Signer and one Verifier shared across
// goroutines, verifying one message concurrently (run under -race).
func TestConcurrentSignVerify(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s, _ := NewSigner(priv)
	v, _ := NewVerifier(priv.Public(), WithKnownCriticalHeaders("x"))
	shared, err := s.Sign([]byte("shared"))
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := MarshalSign1(shared)
	received, err := UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				m, err := s.Sign([]byte("own"))
				if err != nil {
					t.Error(err)
					return
				}
				if err := v.Verify(m); err != nil {
					t.Error(err)
					return
				}
				if err := v.Verify(received); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestErrorChains(t *testing.T) {
	// A deep unprotected header value under RecommendedDecodeLimits:
	// both ErrMalformed and the core sentinel stay visible.
	deep := "84" + "40" + "a1" + "01" + strings.Repeat("81", 20) + "00" + "40" + "40"
	_, err := UnmarshalSign1With(hx(t, deep), RecommendedDecodeLimits)
	if !errors.Is(err, ErrMalformed) || !errors.Is(err, corecbor.ErrMaxNestingDepth) {
		t.Fatalf("err = %v, want ErrMalformed and corecbor.ErrMaxNestingDepth", err)
	}
	if _, err := UnmarshalSign1(hx(t, deep)); err != nil {
		t.Fatalf("UnmarshalSign1 keeps v0.2.2 limits: %v", err)
	}

	// Key errors keep their cause.
	_, _, err = (&AESKWKey{Key: []byte{1, 2, 3}}).WrapKey(make([]byte, 16), KeyWrapOpts{})
	if !errors.Is(err, ErrInvalidKey) || errors.Unwrap(err) == nil {
		t.Fatalf("AES-KW bad key: err = %v", err)
	}
}

func TestDecodeLimits(t *testing.T) {
	big := "84" + "40" + "a1" + "04" + "5a00100000" + strings.Repeat("00", 1<<20) + "40" + "40" // kid of 1 MiB
	data := hx(t, big)
	if _, err := UnmarshalSign1(data); err != nil {
		t.Fatalf("zero limits: %v", err)
	}
	if _, err := UnmarshalSign1With(data, DecodeLimits{}); err != nil {
		t.Fatalf("DecodeLimits{}: %v", err)
	}
	if _, err := UnmarshalSign1With(data, RecommendedDecodeLimits); !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("recommended: err = %v, want ErrMemoryBudgetExceeded", err)
	}

	// Deprecated AllowDuplicateLabels restores v0.2.2 last-wins.
	dup := hx(t, "84"+"45A201270126"+"A0"+"40"+"40") // protected {1: -8, 1: -7}
	if _, err := UnmarshalSign1(dup); !errors.Is(err, ErrDuplicateLabel) {
		t.Fatalf("default: err = %v, want ErrDuplicateLabel", err)
	}
	m, err := UnmarshalSign1With(dup, DecodeLimits{AllowDuplicateLabels: true})
	if err != nil {
		t.Fatalf("AllowDuplicateLabels: %v", err)
	}
	if m.Protected.Algorithm() != AlgES256 {
		t.Fatalf("last-wins: alg = %v, want ES256", m.Protected.Algorithm())
	}
	across := hx(t, "84"+"43A10127"+"A10127"+"40"+"40")
	if _, err := UnmarshalSign1With(across, DecodeLimits{AllowDuplicateLabels: true}); err != nil {
		t.Fatalf("AllowDuplicateLabels across buckets: %v", err)
	}
}
