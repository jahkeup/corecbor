// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"
)

// Proposal 028: fuzz targets for COSE_Key parsing, JWK conversion and the
// typed header accessors.

func FuzzParseKey(f *testing.F) {
	for _, h := range []string{
		webauthnES256AuthData[2*(32+1+4+16+2+32):],
		"A50102200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C025820496BD8AFADF307E5B08C64B0421BF9DC01528A344A43BDA88FADD1669DA253EC",
		"a201042041aa",
		"a2010720410a",
		"a40101200621582011111111111111111111111111111111111111111111111111111111111111110481" + "02",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Add([]byte("\xa4\x01\x01 \x06!X 000000000000000000000000000000000\xfa\xff\xff00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if kk, _, err := ParseKeyPrefix(data, KeepParamsAsReceived()); err == nil {
			kenc, err := kk.MarshalCBOR()
			if err != nil {
				t.Fatalf("MarshalCBOR of a key kept as received: %v", err)
			}
			kk2, err := ParseKey(kenc, KeepParamsAsReceived())
			if err != nil {
				t.Fatalf("re-parse of %x: %v", kenc, err)
			}
			for l, v := range kk.ReceivedParams() {
				if !bytes.Equal(kk2.ReceivedParams()[l], v) {
					t.Fatalf("param %v changed: %x -> %x", l, v, kk2.ReceivedParams()[l])
				}
			}
		}
		k, rest, err := ParseKeyPrefix(data)
		if err != nil {
			return
		}
		if !bytes.HasSuffix(data, rest) {
			t.Fatalf("rest %x is not a suffix of the input", rest)
		}
		enc, err := k.MarshalCBOR()
		if err != nil {
			t.Fatalf("MarshalCBOR of a parsed key: %v", err)
		}
		k2, err := ParseKey(enc)
		if err != nil {
			t.Fatalf("re-parse of %x: %v", enc, err)
		}
		enc2, _ := k2.MarshalCBOR()
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("not idempotent:\n%x\n%x", enc, enc2)
		}
		_, _ = k.Thumbprint(crypto.SHA256)
		_, _ = k.PublicKey()
		_, _ = k.Public()
		_, _ = k.JWK()
		_ = k.Ops()

		// With KeepParamsAsReceived, kept parameters survive a marshal
		// and re-parse byte for byte, and marshalling is idempotent.
		kk, _, err := ParseKeyPrefix(data, KeepParamsAsReceived())
		if err != nil {
			t.Fatalf("KeepParamsAsReceived rejected a key the default accepts: %v", err)
		}
		kenc, err := kk.MarshalCBOR()
		if err != nil {
			t.Fatalf("MarshalCBOR with kept params: %v", err)
		}
		kk2, err := ParseKey(kenc, KeepParamsAsReceived())
		if err != nil {
			t.Fatalf("re-parse of %x: %v", kenc, err)
		}
		if kenc2, _ := kk2.MarshalCBOR(); !bytes.Equal(kenc, kenc2) {
			t.Fatalf("kept: not idempotent:\n%x\n%x", kenc, kenc2)
		}
	})
}

func FuzzKeyFromJWK(f *testing.F) {
	for _, s := range []string{rfc7517ECPublic, rfc7517ECPrivate, rfc7517RSAPublic, rfc8037Ed25519, `{"kty":"oct","k":"AQ"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := KeyFromJWK(data)
		if err != nil {
			return
		}
		j, err := k.JWK()
		if err != nil {
			return // e.g. text key_ops have no reverse mapping issue
		}
		k2, err := KeyFromJWK(j)
		if err != nil {
			t.Fatalf("re-import of %s: %v", j, err)
		}
		a, _ := k.MarshalCBOR()
		b, _ := k2.MarshalCBOR()
		if !bytes.Equal(a, b) {
			t.Fatalf("JWK round trip changed the key:\n%x\n%x", a, b)
		}
	})
}

func FuzzHeaderAccessors(f *testing.F) {
	for _, h := range []string{"a10127", "a20127044161", "a1182182410141a2", "a1182282102041", "a10fa10178", "a1028101"} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := decodeProtected(data, DecodeLimits{})
		if err != nil {
			return
		}
		_ = h.Critical()
		_, _, _ = h.ContentType()
		_, _, _ = h.Type()
		_ = h.IV()
		_ = h.PartialIV()
		_ = h.KeyIDContext()
		_, _ = h.KCWT()
		_, _ = h.KCCS()
		_, _ = h.CWTClaims()
		_, _ = h.X5Chain()
		_, _ = h.X5Bag()
		_, _, _ = h.X5T()
		_, _ = h.X5U()
		_ = h.TimestampTTC()
		_ = h.TimestampCTT()
	})
}
