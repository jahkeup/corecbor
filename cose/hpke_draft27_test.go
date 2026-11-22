// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Appendix C inputs of draft-ietf-cose-hpke-27.
var (
	hpkeVecPlaintext = []byte("hpke test payload")
	hpkeVecAAD       = []byte("external-aad")
	hpkeVecInfo      = []byte("external-info")
	hpkeVecHPKEAAD   = []byte("external-hpke-aad")
)

func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hpkeSuiteByLabel(t *testing.T, label string) HPKESuite {
	t.Helper()
	for s := HPKE0; s <= HPKE7; s++ {
		if strings.TrimSuffix(label, "-KE") == s.String() {
			return s
		}
	}
	t.Fatalf("unknown suite %q", label)
	return 0
}

// TestHPKEDraft27 decrypts every Appendix C test vector. mode_psk
// vectors and the X448 suites (HPKE-5/6) must fail with
// ErrUnsupportedAlgorithm: Go's crypto/hpke implements mode_base only,
// and Go has no X448.
func TestHPKEDraft27(t *testing.T) {
	var passed, unsupported, nonconformantIV, contentSkipped int
	for _, v := range hpkeDraft27Vectors {
		t.Run(v.title, func(t *testing.T) {
			suite := hpkeSuiteByLabel(t, v.suite)
			ke := strings.HasSuffix(v.suite, "-KE")
			expectUnsupported := v.psk || suite == HPKE5 || suite == HPKE6

			key, err := ParseKey(mustHexT(t, v.key))
			if err != nil {
				if expectUnsupported {
					unsupported++
					return
				}
				t.Fatalf("ParseKey: %v", err)
			}
			opts := []EncryptOption{WithDraftHPKE27()}
			if v.extAAD {
				opts = append(opts, WithEncryptExternalAAD(hpkeVecAAD))
			}

			var got []byte
			if ke {
				msg, uerr := UnmarshalEncrypt(mustHexT(t, v.ciphertext))
				if uerr != nil {
					t.Fatalf("UnmarshalEncrypt: %v", uerr)
				}
				r := &HPKERecipient{Suite: suite, PrivateKey: key}
				if v.extInfo {
					r.ExtraInfo = hpkeVecInfo
				}
				if v.extHPKEAAD {
					r.AAD = hpkeVecHPKEAAD
				}
				got, err = DecryptMulti(msg, r, 0, opts...)
				if expectUnsupported && errors.Is(err, ErrAlgorithmMismatch) && msg.Protected.Algorithm() == AlgChaCha20Poly1305 {
					// The content alg is rejected before the recipient is
					// reached; check the recipient's own verdict.
					_, err = hpkeVectorFallback(t, msg, r, v.extAAD)
				}
				if !expectUnsupported && err != nil {
					// The draft's vectors use 16-byte AES-GCM IVs at layer 0
					// (RFC 9053 §4.1 requires 96 bits) and ChaCha20-Poly1305
					// content (not in Go's standard library). DecryptMulti
					// correctly rejects both; verify the HPKE layer directly.
					got, err = hpkeVectorFallback(t, msg, r, v.extAAD)
					if errors.Is(err, errHPKEContentSkipped) {
						contentSkipped++
						return
					}
					if err == nil {
						nonconformantIV++
					}
				}
			} else {
				msg, uerr := UnmarshalEncrypt0(mustHexT(t, v.ciphertext))
				if uerr != nil {
					t.Fatalf("UnmarshalEncrypt0: %v", uerr)
				}
				if v.extInfo {
					opts = append(opts, WithHPKEInfo(hpkeVecInfo))
				}
				got, err = HPKEOpen(msg, key, opts...)
			}
			if expectUnsupported {
				if !errors.Is(err, ErrUnsupportedAlgorithm) {
					t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
				}
				unsupported++
				return
			}
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, hpkeVecPlaintext) {
				t.Fatalf("plaintext = %q", got)
			}
			passed++
		})
	}
	t.Logf("draft-27 vectors: %d decrypted (%d via the 16-byte-IV fallback), %d with only the HPKE layer checked (ChaCha20-Poly1305 content), %d unsupported (mode_psk, X448)",
		passed, nonconformantIV, contentSkipped, unsupported)
	if passed == 0 {
		t.Fatal("no vector decrypted")
	}
}

var errHPKEContentSkipped = errors.New("content layer skipped")

// hpkeVectorFallback unwraps the CEK with the HPKE recipient (the part
// this package implements) and decrypts layer 0 itself, tolerating the
// vectors' 16-byte AES-GCM IV. ChaCha20-Poly1305 content returns
// errHPKEContentSkipped after a successful unwrap.
func hpkeVectorFallback(t *testing.T, msg *Encrypt, r *HPKERecipient, extAAD bool) ([]byte, error) {
	t.Helper()
	contentAlg := msg.Protected.Algorithm()
	rec := &msg.Recipients[0]
	protBytes, err := rec.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	cek, err := r.UnwrapKey(rec.Ciphertext, rec.Unprotected, KeyUnwrapOpts{
		CEKAlgorithm: contentAlg, protected: string(protBytes),
		legacy: legacyEncoding{draftHPKE27: true},
	})
	if err != nil {
		return nil, fmt.Errorf("HPKE unwrap: %w", err)
	}
	if contentAlg == AlgChaCha20Poly1305 {
		if len(cek) != 32 {
			return nil, fmt.Errorf("ChaCha20-Poly1305 CEK is %d bytes", len(cek))
		}
		return nil, errHPKEContentSkipped
	}
	iv, ok := headerBytes(&msg.Protected, &msg.Unprotected, headerLabelIV)
	if !ok {
		return nil, errors.New("no IV")
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	bodyProt, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	var ext []byte
	if extAAD {
		ext = hpkeVecAAD
	}
	aad, err := buildEncStructureMulti(bodyProt, ext)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, msg.Ciphertext, aad)
}

// TestHPKERequiresDraftSelector: without WithDraftHPKE27 every HPKE
// entry point is ErrUnsupportedAlgorithm.
func TestHPKERequiresDraftSelector(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := NewKeyFromPublic(priv.PublicKey())
	if _, err := HPKESeal([]byte("x"), pub, HPKE0); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("HPKESeal: %v", err)
	}
	if _, err := HPKEOpen(&Encrypt0{}, pub); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("HPKEOpen: %v", err)
	}
	r := &HPKERecipient{Suite: HPKE0, PublicKey: pub}
	if _, err := EncryptMulti([]byte("x"), AlgA128GCM, []KeyDeriver{r}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("EncryptMulti: %v", err)
	}
}
