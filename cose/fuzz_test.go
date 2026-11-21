// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"testing"
)

// Proposal 027 Phase 4 fuzz targets (Phase 1 surfaces).

func addCOSESeeds(f *testing.F) {
	for _, h := range []string{
		// cose-wg/Examples vectors (see TestCOSEWGExamples).
		"D28445A201270300A10442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D",
		"D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F",
		"D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
		"D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
		// Malformed shapes from the 2026-11-20 review.
		"d28440a1410101f640",        // bstr label
		"d28440a1820102" + "01f640", // array label
		"d28440a11bffffffffffffffff01f640",
		"d8608440a1054100" + "4180" + "81834040" + "40", // Encrypt, 1-byte IV
		"d8628440a0f680",                                // Sign with no signatures
		"d8618540a0f64081834040" + "40",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
}

var (
	fuzzVerifier, _ = NewVerifier(hardEdPub)
	fuzzECDHPriv, _ = ecdh.P256().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	fuzzDerivers    = []KeyDeriver{
		&DirectKey{Key: hardAESKey},
		&DirectKey{Key: hardMACKey},
		&AESKWKey{Key: hardAESKey},
		&PBES2Key{Password: []byte("pw"), MaxCount: 1000},
		&ECDHESKey{PrivateKey: fuzzECDHPriv},
		&ECDHESKey{},
		&HPKEKey{PrivateKey: fuzzECDHPriv},
	}
)

// FuzzUnmarshalNeverPanics: arbitrary bytes into every Unmarshal* return
// a message or a typed error, and decoded messages run through every
// verify/decrypt path without panicking.
func FuzzUnmarshalNeverPanics(f *testing.F) {
	addCOSESeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := UnmarshalSign1(data); err == nil {
			_ = fuzzVerifier.Verify(m)
			_ = fuzzVerifier.VerifyDetached(m, nil)
			_, _ = MarshalSign1(m)
		} else if !errors.Is(err, ErrMalformed) {
			t.Fatalf("UnmarshalSign1: untyped error %v", err)
		}
		if m, err := UnmarshalMac0(data); err == nil {
			_ = VerifyMAC0(m, hardMACKey, AlgHMAC256)
			_, _ = MarshalMac0(m)
		} else if !errors.Is(err, ErrMalformed) {
			t.Fatalf("UnmarshalMac0: untyped error %v", err)
		}
		if m, err := UnmarshalEncrypt0(data); err == nil {
			iv, _ := m.Unprotected.Get(int64(5)).([]byte)
			_, _ = DecryptEncrypt0(m, hardAESKey, iv, AlgA128GCM)
			_, _ = MarshalEncrypt0(m)
		} else if !errors.Is(err, ErrMalformed) {
			t.Fatalf("UnmarshalEncrypt0: untyped error %v", err)
		}
		if m, err := UnmarshalSign(data); err == nil {
			_, _ = VerifyMulti(m, []*Verifier{fuzzVerifier})
			_, _ = VerifyMulti(m, []*Verifier{fuzzVerifier}, RequireAll)
			_, _ = MarshalSign(m)
		} else if !errors.Is(err, ErrMalformed) {
			t.Fatalf("UnmarshalSign: untyped error %v", err)
		}
		if m, err := UnmarshalMac(data); err == nil {
			for i := range m.Recipients {
				for _, d := range fuzzDerivers {
					_ = VerifyMACMulti(m, d, i)
				}
			}
			_, _ = MarshalMac(m)
		} else if !errors.Is(err, ErrMalformed) {
			t.Fatalf("UnmarshalMac: untyped error %v", err)
		}
		if m, err := UnmarshalEncrypt(data); err == nil {
			for i := range m.Recipients {
				for _, d := range fuzzDerivers {
					_, _ = DecryptMulti(m, d, i)
				}
			}
			_, _ = MarshalEncrypt(m)
		} else if !errors.Is(err, ErrMalformed) {
			t.Fatalf("UnmarshalEncrypt: untyped error %v", err)
		}
	})
}

// FuzzHeadersDecode: an arbitrary protected bstr either decodes or is
// rejected, never panics, and decoded headers re-yield the same bytes.
func FuzzHeadersDecode(f *testing.F) {
	for _, h := range []string{"", "a0", "a10126", "a204416b0127", "a1410101", "a11bffffffffffffffff01"} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := decodeProtected(data)
		if err != nil {
			return
		}
		got, err := h.encodeProtected()
		if err != nil {
			t.Fatalf("encodeProtected after decode: %v", err)
		}
		if h.IsEmpty() {
			if len(got) != 0 {
				t.Fatalf("empty headers yield %x, want zero-length", got)
			}
			return
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("protected bytes changed: got %x, want %x", got, data)
		}
	})
}

// FuzzSign1RoundTrip: Sign → Marshal → Unmarshal → Verify succeeds for
// any payload and external data, attached or detached.
func FuzzSign1RoundTrip(f *testing.F) {
	f.Add([]byte("payload"), []byte(nil), false)
	f.Add([]byte{}, []byte("aad"), true)
	f.Fuzz(func(t *testing.T, payload, external []byte, detach bool) {
		s, err := NewSigner(hardEdPriv, WithSignerExternalData(external))
		if err != nil {
			t.Fatal(err)
		}
		v, err := NewVerifier(hardEdPub, WithVerifierExternalData(external))
		if err != nil {
			t.Fatal(err)
		}
		if payload == nil {
			payload = []byte{}
		}
		msg, err := s.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		if detach {
			msg.Payload = nil
		}
		data, err := MarshalSign1(msg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnmarshalSign1(data)
		if err != nil {
			t.Fatal(err)
		}
		if detach {
			if err := v.Verify(got); !errors.Is(err, ErrMissingPayload) {
				t.Fatalf("Verify(detached) = %v, want ErrMissingPayload", err)
			}
			err = v.VerifyDetached(got, payload)
			if err != nil {
				t.Fatalf("VerifyDetached: %v", err)
			}
			return
		}
		if err := v.Verify(got); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
}
