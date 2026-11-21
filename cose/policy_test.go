// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 027 Phase 2: alg binding (H2), crit (H3), duplicate labels
// (H4), external AAD on multi-recipient verify/decrypt (H7), HMAC keys.

// cosewgP256 is the P-256 key "11" used by the cose-wg Examples and
// RFC 9052 Appendix C.
func cosewgP256(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	x := b64u(t, "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
	y := b64u(t, "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestCOSEWGSign1FailVectors embeds cose-wg/Examples sign1-tests
// sign-fail-* (public domain). Every one must fail; the two that tamper
// with the protected alg must fail on the alg check.
func TestCOSEWGSign1FailVectors(t *testing.T) {
	const sig = "58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36"
	cases := []struct {
		name    string
		hex     string
		wantErr error // nil: any error
	}{
		{"sign-fail-01 wrong CBOR tag", "D903E68443A10126A10442313154546869732069732074686520636F6E74656E742E" + sig, ErrMalformed},
		{"sign-fail-02 changed signature", "D28443A10126A10442313154546869732069732074686520636F6E74656E742F" + sig, ErrVerification},
		{"sign-fail-03 alg changed to -999", "D28445A1013903E6A10442313154546869732069732074686520636F6E74656E742E" + sig, ErrAlgorithmMismatch},
		{"sign-fail-04 alg changed to \"unknown\"", "D2844AA10167756E6B6E6F776EA10442313154546869732069732074686520636F6E74656E742E" + sig, ErrAlgorithmMismatch},
		{"sign-fail-06 protected attribute added", "D28445A201260300A10442313154546869732069732074686520636F6E74656E742E" + sig, ErrVerification},
		{"sign-fail-07 protected attribute removed", "D28443A10126A10442313154546869732069732074686520636F6E74656E742E58406520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B", ErrVerification},
	}
	v, err := NewVerifier(cosewgP256(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := UnmarshalSign1(hx(t, tc.hex))
			if err == nil {
				err = v.Verify(msg)
			}
			if err == nil {
				t.Fatal("verified; want failure")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestRFC9052CritExample is RFC 9052 Appendix C.1.3: a COSE_Sign whose
// body protected bucket marks the text label "reserved" critical.
func TestRFC9052CritExample(t *testing.T) {
	data := hx(t, "D862"+"84"+
		"56A2687265736572766564F40281687265736572766564"+
		"A0"+
		"54546869732069732074686520636F6E74656E742E"+
		"8183"+"43A10126"+"A1044231"+"31"+
		"58403FC54702AA56E1B2CB20284294C9106A63F91BAC658D69351210A031D8FC7C5FF3E4BE39445B1A3E83E1510D1ACA2F2E8A7C081C7645042B18ABA9D1FAD1BD9C")
	msg, err := UnmarshalSign(data)
	if err != nil {
		t.Fatal(err)
	}

	plain, _ := NewVerifier(cosewgP256(t))
	_, err = VerifyMulti(msg, []*Verifier{plain})
	if !errors.Is(err, ErrVerification) || !errors.Is(err, ErrCriticalHeader) {
		t.Fatalf("without declaring \"reserved\": err = %v, want ErrVerification wrapping ErrCriticalHeader", err)
	}

	known, _ := NewVerifier(cosewgP256(t), WithKnownCriticalHeaders("reserved"))
	if idx, err := VerifyMulti(msg, []*Verifier{known}); err != nil || len(idx) != 1 {
		t.Fatalf("declaring \"reserved\": idx %v, err %v", idx, err)
	}

	legacy, _ := NewVerifier(cosewgP256(t), WithLegacyIgnoreCritical())
	if _, err := VerifyMulti(msg, []*Verifier{legacy}); err != nil {
		t.Fatalf("legacy: %v", err)
	}
}

// signWithHeaders signs payload as a Sign1 whose buckets are exactly
// prot and unprot, so tests can put any alg or crit in either bucket.
func signWithHeaders(t *testing.T, s *Signer, prot, unprot Headers, payload []byte) *Sign1 {
	t.Helper()
	pb, err := prot.encodeProtected()
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := encodeSigStructure(s.enc, pb, s.external, payload)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.signBytes(context.Background(), s.alg, tbs)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through the wire format, as a receiver would see it.
	wire, err := MarshalSign1(&Sign1{Protected: prot, Unprotected: unprot, Payload: payload, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func hdr(kv ...any) Headers {
	var h Headers
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestAlgBinding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := NewSigner(key)
	payload := []byte("payload")

	cases := []struct {
		name         string
		prot, unprot Headers
		opts         []VerifierOption
		wantErr      error
	}{
		{"protected alg matches key", hdr(int64(1), int64(AlgES256)), Headers{}, nil, nil},
		{"no alg: key's algorithm", Headers{}, Headers{}, nil, nil},
		{"unprotected-only alg equal to key", Headers{}, hdr(int64(1), int64(AlgES256)), nil, nil},
		{"unprotected-only alg different", Headers{}, hdr(int64(1), int64(AlgES384)), nil, ErrAlgorithmMismatch},
		{"protected alg different", hdr(int64(1), int64(AlgES384)), Headers{}, nil, ErrAlgorithmMismatch},
		{"text alg", hdr(int64(1), "ES256"), Headers{}, nil, ErrAlgorithmMismatch},
		{"allow-list excludes key alg", hdr(int64(1), int64(AlgES256)), Headers{}, []VerifierOption{WithAllowedAlgorithms(AlgES384)}, ErrAlgorithmMismatch},
		{"allow-list includes key alg", hdr(int64(1), int64(AlgES256)), Headers{}, []VerifierOption{WithAllowedAlgorithms(AlgES256, AlgES384)}, nil},
		{"legacy ignores a mismatched alg", hdr(int64(1), int64(AlgES384)), Headers{}, []VerifierOption{WithLegacyAlgorithmFromKey()}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := signWithHeaders(t, s, tc.prot, tc.unprot, payload)
			v, err := NewVerifier(key.Public(), tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			err = v.Verify(msg)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify err = %v, want %v", err, tc.wantErr)
			}
		})
	}

	// alg in both buckets can't be built through MarshalSign1 →
	// UnmarshalSign1 (H4 rejects it at decode), so check the verifier on
	// a locally built message.
	both := &Sign1{Protected: hdr(int64(1), int64(AlgES256)), Unprotected: hdr(int64(1), int64(AlgES256)), Payload: payload}
	v, _ := NewVerifier(key.Public())
	if err := v.Verify(both); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("alg in both buckets: err = %v, want ErrAlgorithmMismatch", err)
	}
}

func TestCritHeader(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := NewSigner(priv)
	payload := []byte("payload")
	alg := int64(AlgEdDSA)

	crit := func(labels ...corecbor.Value) corecbor.Value { return corecbor.MakeArray(labels...) }
	cases := []struct {
		name         string
		prot, unprot Headers
		opts         []VerifierOption
		wantErr      error
	}{
		{"standard label listed", hdr(int64(1), alg, int64(2), crit(corecbor.Uint(3)), int64(3), "text/plain"), Headers{}, nil, nil},
		{"unknown label", hdr(int64(1), alg, int64(2), crit(corecbor.Uint(99)), int64(99), "x"), Headers{}, nil, ErrCriticalHeader},
		{"unknown label declared", hdr(int64(1), alg, int64(2), crit(corecbor.Uint(99)), int64(99), "x"), Headers{}, []VerifierOption{WithKnownCriticalHeaders(99)}, nil},
		{"text label declared", hdr(int64(1), alg, int64(2), crit(corecbor.Text("ext")), "ext", int64(1)), Headers{}, []VerifierOption{WithKnownCriticalHeaders("ext")}, nil},
		{"listed label absent", hdr(int64(1), alg, int64(2), crit(corecbor.Uint(99))), Headers{}, []VerifierOption{WithKnownCriticalHeaders(99)}, ErrCriticalHeader},
		{"listed label only unprotected", hdr(int64(1), alg, int64(2), crit(corecbor.Uint(99))), hdr(int64(99), "x"), []VerifierOption{WithKnownCriticalHeaders(99)}, ErrCriticalHeader},
		{"empty crit", hdr(int64(1), alg, int64(2), crit()), Headers{}, nil, ErrCriticalHeader},
		{"crit not an array", hdr(int64(1), alg, int64(2), int64(3)), Headers{}, nil, ErrCriticalHeader},
		{"crit in unprotected bucket", hdr(int64(1), alg), hdr(int64(2), crit(corecbor.Uint(3))), nil, ErrCriticalHeader},
		{"legacy ignores crit", hdr(int64(1), alg, int64(2), crit(corecbor.Uint(99)), int64(99), "x"), Headers{}, []VerifierOption{WithLegacyIgnoreCritical()}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := signWithHeaders(t, s, tc.prot, tc.unprot, payload)
			v, err := NewVerifier(priv.Public(), tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			err = v.Verify(msg)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDuplicateLabels(t *testing.T) {
	// Sign1 = [protected, unprotected, payload, signature]; the
	// signature is never checked because decoding must fail first.
	sign1 := func(prot, unprot string) []byte {
		return hx(t, "84"+prot+unprot+"40"+"40")
	}
	cases := map[string][]byte{
		// protected {1: -8, 1: -8}
		"within protected": sign1("45A201270127", "A0"),
		// protected {1: -8, 24(1): -8}: 01 and 1801 are the same label
		"within protected, non-shortest": sign1("46A20127180127", "A0"),
		// unprotected {4: h'', 4: h''}
		"within unprotected": sign1("40", "A204400440"),
		// protected {1: -8}, unprotected {1: -8}
		"across buckets": sign1("43A10127", "A10127"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalSign1(data)
			if !errors.Is(err, ErrDuplicateLabel) || !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed wrapping ErrDuplicateLabel", err)
			}
		})
	}
}

func TestMACMultiPolicy(t *testing.T) {
	payload := []byte("payload")
	recipient := &AESKWKey{Key: make([]byte, 16)}

	t.Run("header-selected HMAC 256/64 rejected by default", func(t *testing.T) {
		msg, err := ComputeMACMulti(payload, nil, AlgHMAC256_64, []KeyDeriver{recipient})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyMACMulti(msg, recipient, 0); !errors.Is(err, ErrAlgorithmMismatch) {
			t.Fatalf("default: err = %v, want ErrAlgorithmMismatch", err)
		}
		if err := VerifyMACMulti(msg, recipient, 0, WithMACAlgorithms(AlgHMAC256_64)); err != nil {
			t.Fatalf("listed: %v", err)
		}
	})

	t.Run("external AAD", func(t *testing.T) {
		aad := []byte("context")
		msg, err := ComputeMACMulti(payload, nil, AlgHMAC256, []KeyDeriver{recipient}, WithMACExternalAAD(aad))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyMACMulti(msg, recipient, 0, WithMACExternalAAD(aad)); err != nil {
			t.Fatalf("matching AAD: %v", err)
		}
		if err := VerifyMACMulti(msg, recipient, 0); !errors.Is(err, ErrMACVerification) {
			t.Fatalf("missing AAD: err = %v, want ErrMACVerification", err)
		}
	})

	t.Run("alg only in unprotected bucket", func(t *testing.T) {
		msg, err := ComputeMACMulti(payload, nil, AlgHMAC256, []KeyDeriver{recipient})
		if err != nil {
			t.Fatal(err)
		}
		msg.Protected = Headers{}
		msg.Unprotected.SetAlgorithm(AlgHMAC256)
		if err := VerifyMACMulti(msg, recipient, 0); !errors.Is(err, ErrAlgorithmMismatch) {
			t.Fatalf("err = %v, want ErrAlgorithmMismatch", err)
		}
	})
}

func TestDecryptMultiPolicy(t *testing.T) {
	plaintext := []byte("secret")
	recipient := &AESKWKey{Key: make([]byte, 16)}

	t.Run("external AAD", func(t *testing.T) {
		aad := []byte("context")
		msg, err := EncryptMulti(plaintext, AlgA128GCM, []KeyDeriver{recipient}, WithEncryptExternalAAD(aad))
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecryptMulti(msg, recipient, 0, WithEncryptExternalAAD(aad))
		if err != nil || string(got) != string(plaintext) {
			t.Fatalf("matching AAD: %q, %v", got, err)
		}
		if _, err := DecryptMulti(msg, recipient, 0); !errors.Is(err, ErrDecryption) {
			t.Fatalf("missing AAD: err = %v, want ErrDecryption", err)
		}
	})

	t.Run("allow-list", func(t *testing.T) {
		msg, err := EncryptMulti(plaintext, AlgA128GCM, []KeyDeriver{recipient})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecryptMulti(msg, recipient, 0, WithEncryptAlgorithms(AlgA256GCM)); !errors.Is(err, ErrAlgorithmMismatch) {
			t.Fatalf("err = %v, want ErrAlgorithmMismatch", err)
		}
	})

	t.Run("crit on recipient layer", func(t *testing.T) {
		msg, err := EncryptMulti(plaintext, AlgA128GCM, []KeyDeriver{recipient})
		if err != nil {
			t.Fatal(err)
		}
		msg.Recipients[0].Protected.Set(int64(2), corecbor.MakeArray(corecbor.Uint(99)))
		msg.Recipients[0].Protected.Set(int64(99), "x")
		if _, err := DecryptMulti(msg, recipient, 0); !errors.Is(err, ErrCriticalHeader) {
			t.Fatalf("err = %v, want ErrCriticalHeader", err)
		}
		if _, err := DecryptMulti(msg, recipient, 0, WithEncryptKnownCriticalHeaders(99)); err != nil {
			t.Fatalf("declared: %v", err)
		}
	})
}

func TestMAC0Policy(t *testing.T) {
	payload := []byte("payload")
	key := make([]byte, 32)

	if _, err := ComputeMAC0(payload, nil, AlgHMAC256); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ComputeMAC0 nil key: err = %v, want ErrInvalidKey", err)
	}
	if _, err := ComputeMAC0(payload, []byte{}, AlgHMAC256); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ComputeMAC0 empty key: err = %v, want ErrInvalidKey", err)
	}
	short := make([]byte, 16)
	msg, err := ComputeMAC0(payload, short, AlgHMAC256)
	if err != nil {
		t.Fatalf("short key accepted by default (RFC 9053 §3.1 SHOULD): %v", err)
	}
	if err := VerifyMAC0(msg, short, AlgHMAC256, WithStrictMACKeyLength()); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("strict: err = %v, want ErrInvalidKey", err)
	}
	if err := VerifyMAC0(msg, nil, AlgHMAC256); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("VerifyMAC0 nil key: err = %v, want ErrInvalidKey", err)
	}

	msg, err = ComputeMAC0(payload, key, AlgHMAC256)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMAC0(msg, key, AlgHMAC384); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("caller alg differs from header: err = %v, want ErrAlgorithmMismatch", err)
	}
	if err := VerifyMAC0(msg, key, AlgHMAC256, WithMACAlgorithms(AlgHMAC512)); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("not allowed: err = %v, want ErrAlgorithmMismatch", err)
	}
	if err := VerifyMAC0(msg, key, AlgHMAC384, WithLegacyMACHeaders()); !errors.Is(err, ErrMACVerification) {
		t.Fatalf("legacy: err = %v, want ErrMACVerification (v0.2.2)", err)
	}
}

func TestEncrypt0AlgBinding(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	msg, err := EncryptEncrypt0([]byte("x"), key, nonce, AlgA128GCM)
	if err != nil {
		t.Fatal(err)
	}
	msg.Protected = Headers{}
	msg.Protected.SetAlgorithm(AlgA256GCM)
	if _, err := DecryptEncrypt0(msg, key, nonce, AlgA128GCM); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("err = %v, want ErrAlgorithmMismatch", err)
	}
}
