// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// rfc9052AppendixB is the three-layer COSE_Encrypt of RFC 9052
// Appendix B: an AES-KW recipient whose key comes from a nested
// ECDH-ES recipient.
func rfc9052AppendixB(t *testing.T) []byte {
	t.Helper()
	A, B, M := corecbor.MakeArray, corecbor.Bytes, corecbor.MakeMap
	e := func(k int64, v corecbor.Value) corecbor.MapEntry {
		return corecbor.MapEntry{Key: goToCBOR(k), Value: v}
	}
	epk := M(e(1, goToCBOR(int64(2))), e(-1, goToCBOR(int64(1))),
		e(-2, B(hx(t, "b2add44368ea6d641f9ca9af308b4079aeb519f11e9b8a55a600b21233e86e68"))),
		e(-3, corecbor.Bool(false)))
	inner := A(B(hx(t, "a1013818")), M(e(-1, epk), e(4, B([]byte("meriadoc.brandybuck@buckland.example")))), B(nil))
	kw := A(B(nil), M(e(1, goToCBOR(int64(-3)))), B(hx(t, "dbd43c4e9d719c27c6275c67d628d493f090593db8218f11")), A(inner))
	msg := A(B(hx(t, "a10101")), M(e(5, B(hx(t, "02d1f7e6f26c43d4868d87ce")))),
		B(hx(t, "64f84d913ba60a76070a9a48f26e97e863e2852948658f0811139868826e89218a75715b")), A(kw))
	return encodeCBOR(t, corecbor.MakeTag(96, msg))
}

// Proposal 037 S3: a COSE_recipient with nested recipients (RFC 9052
// §5.1) is parsed and written back instead of failing the message.
func TestSpec037NestedRecipients(t *testing.T) {
	data := rfc9052AppendixB(t)
	if len(data) != 183 {
		t.Fatalf("Appendix B encoding is %d bytes, RFC says 183", len(data))
	}
	msg, err := UnmarshalEncrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Recipients) != 1 || len(msg.Recipients[0].Recipients) != 1 {
		t.Fatalf("recipients = %+v", msg.Recipients)
	}
	if got := msg.Recipients[0].Recipients[0].Protected.Algorithm(); got != AlgECDH_ES_HKDF_256 {
		t.Fatalf("nested alg = %v", got)
	}
	out, err := MarshalEncrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("round trip:\n got %x\nwant %x", out, data)
	}

	// Nested recipients count toward MaxRecipients.
	if _, err := UnmarshalEncryptWith(data, DecodeLimits{MaxRecipients: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("MaxRecipients 1: err = %v, want ErrLimitExceeded", err)
	}
	// A nested recipients element that is present must be non-empty.
	A, B := corecbor.MakeArray, corecbor.Bytes
	empty := encodeCBOR(t, corecbor.MakeTag(96, A(B(nil), corecbor.MakeMap(), B(nil),
		A(A(B(nil), corecbor.MakeMap(), B(nil), A())))))
	if _, err := UnmarshalEncrypt(empty); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty nested recipients: err = %v, want ErrMalformed", err)
	}
	// The same structure in a COSE_Mac.
	mac := encodeCBOR(t, corecbor.MakeTag(97, A(B(hx(t, "a10105")), corecbor.MakeMap(), B([]byte("p")), B(make([]byte, 32)),
		A(A(B(nil), corecbor.MakeMap(), B(nil), A(A(B(nil), corecbor.MakeMap(), B(nil))))))))
	m, err := UnmarshalMac(mac)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := MarshalMac(m); err != nil || !bytes.Equal(out, mac) {
		t.Fatalf("MAC round trip: %x, %v", out, err)
	}
}
