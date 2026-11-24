// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jahkeup/corecbor"
)

// Proposal 027 Phase 1 regression tests.

func hx(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b64u(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encodeCBOR(t testing.TB, v corecbor.Value) []byte {
	t.Helper()
	b, err := corecbor.New(corecbor.ModeCoreDeterministic).Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var (
	hardEdPriv = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	hardEdPub  = hardEdPriv.Public().(ed25519.PublicKey)
	hardMACKey = []byte("0123456789abcdef0123456789abcdef")
	hardAESKey = []byte("0123456789abcdef")
	hardIV     = []byte("0123456789ab")
	hardBody   = []byte("payload")
)

// Each foreign protected map below is valid CBOR but not in Core
// Deterministic order ({4: h'6b', 1: alg}), as other encoders emit.
// v0.2.2 re-encoded it before verifying and so rejected every one.
func foreignProtected(alg int64) []byte {
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	algBytes, _ := enc.Encode(nil, goToCBOR(alg))
	return append([]byte{0xa2, 0x04, 0x41, 0x6b, 0x01}, algBytes...)
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func gcmSeal(t *testing.T, key, iv, pt, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return g.Seal(nil, iv, pt, aad)
}

func TestVerifyForeignProtectedOrder(t *testing.T) {
	B := corecbor.Bytes
	T := corecbor.Text
	A := corecbor.MakeArray
	empty := corecbor.MakeMap()
	ivMap := corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(5), Value: B(hardIV)})
	// Recipient using a direct key: [h'', {1: -6}, h''].
	direct := A(B(nil), corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.NegInt(5)}), B(nil))

	cases := map[string]func(t *testing.T) error{
		"Sign1": func(t *testing.T) error {
			prot := foreignProtected(int64(AlgEdDSA))
			sig := ed25519.Sign(hardEdPriv, encodeCBOR(t, A(T("Signature1"), B(prot), B(nil), B(hardBody))))
			msg, err := UnmarshalSign1(encodeCBOR(t, corecbor.MakeTag(18, A(B(prot), empty, B(hardBody), B(sig)))))
			if err != nil {
				return err
			}
			v, _ := NewVerifier(hardEdPub)
			return v.Verify(msg)
		},
		"Mac0": func(t *testing.T) error {
			prot := foreignProtected(int64(AlgHMAC256))
			tag := hmacSHA256(hardMACKey, encodeCBOR(t, A(T("MAC0"), B(prot), B(nil), B(hardBody))))
			msg, err := UnmarshalMac0(encodeCBOR(t, corecbor.MakeTag(17, A(B(prot), empty, B(hardBody), B(tag)))))
			if err != nil {
				return err
			}
			return VerifyMAC0(msg, hardMACKey, AlgHMAC256)
		},
		"Encrypt0": func(t *testing.T) error {
			prot := foreignProtected(int64(AlgA128GCM))
			ct := gcmSeal(t, hardAESKey, hardIV, hardBody, encodeCBOR(t, A(T("Encrypt0"), B(prot), B(nil))))
			msg, err := UnmarshalEncrypt0(encodeCBOR(t, corecbor.MakeTag(16, A(B(prot), ivMap, B(ct)))))
			if err != nil {
				return err
			}
			_, err = DecryptEncrypt0(msg, hardAESKey, hardIV, AlgA128GCM)
			return err
		},
		"Sign": func(t *testing.T) error {
			body := hx(t, "a204416b0300") // {4: h'6b', 3: 0}
			sprot := foreignProtected(int64(AlgEdDSA))
			sig := ed25519.Sign(hardEdPriv, encodeCBOR(t, A(T("Signature"), B(body), B(sprot), B(nil), B(hardBody))))
			msg, err := UnmarshalSign(encodeCBOR(t, corecbor.MakeTag(98, A(B(body), empty, B(hardBody), A(A(B(sprot), empty, B(sig)))))))
			if err != nil {
				return err
			}
			v, _ := NewVerifier(hardEdPub)
			_, err = VerifyMulti(msg, []*Verifier{v})
			return err
		},
		"Mac": func(t *testing.T) error {
			prot := foreignProtected(int64(AlgHMAC256))
			tag := hmacSHA256(hardMACKey, encodeCBOR(t, A(T("MAC"), B(prot), B(nil), B(hardBody))))
			msg, err := UnmarshalMac(encodeCBOR(t, corecbor.MakeTag(97, A(B(prot), empty, B(hardBody), B(tag), A(direct)))))
			if err != nil {
				return err
			}
			return VerifyMACMulti(msg, &DirectKey{Key: hardMACKey}, 0)
		},
		"Encrypt": func(t *testing.T) error {
			prot := foreignProtected(int64(AlgA128GCM))
			ct := gcmSeal(t, hardAESKey, hardIV, hardBody, encodeCBOR(t, A(T("Encrypt"), B(prot), B(nil))))
			msg, err := UnmarshalEncrypt(encodeCBOR(t, corecbor.MakeTag(96, A(B(prot), ivMap, B(ct), A(direct)))))
			if err != nil {
				return err
			}
			_, err = DecryptMulti(msg, &DirectKey{Key: hardAESKey}, 0)
			return err
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(t); err != nil {
				t.Fatalf("foreign-ordered protected map: %v", err)
			}
		})
	}
}

// A protected bucket holding an explicitly encoded empty map (h'a0')
// is accepted, and the signed structure uses a zero-length bstr for it
// (RFC 9052 §3, §4.4), as cose-wg sign-pass-01 checks.
func TestVerifyProtectedEncodedEmptyMap(t *testing.T) {
	prot := []byte{0xa0}
	A, B, T := corecbor.MakeArray, corecbor.Bytes, corecbor.Text
	sig := ed25519.Sign(hardEdPriv, encodeCBOR(t, A(T("Signature1"), B(nil), B(nil), B(hardBody))))
	msg, err := UnmarshalSign1(encodeCBOR(t, corecbor.MakeTag(18, A(B(prot), corecbor.MakeMap(), B(hardBody), B(sig)))))
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Protected.IsEmpty() || string(msg.Protected.Raw()) != "\xa0" {
		t.Fatalf("Protected: empty=%v raw=%x", msg.Protected.IsEmpty(), msg.Protected.Raw())
	}
	v, _ := NewVerifier(hardEdPub)
	if err := v.Verify(msg); err != nil {
		t.Fatal(err)
	}
	// Re-marshaling keeps the received bytes, so the signature stays valid.
	out, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := UnmarshalSign1(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(msg2); err != nil {
		t.Fatalf("after re-marshal: %v", err)
	}
	// Modifying the headers discards the received bytes.
	msg.Protected.SetKeyID([]byte("k"))
	if msg.Protected.Raw() != nil {
		t.Fatal("Set must invalidate Raw()")
	}
}

// Interop vectors from cose-wg/Examples (public domain, Unlicense),
// https://github.com/cose-wg/Examples. Verify-only.
func TestCOSEWGExamples(t *testing.T) {
	content := []byte("This is the content.")

	t.Run("eddsa-examples/eddsa-sig-01", func(t *testing.T) {
		msg, err := UnmarshalSign1(hx(t, "D28445A201270300A10442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D"))
		if err != nil {
			t.Fatal(err)
		}
		v, _ := NewVerifier(ed25519.PublicKey(hx(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")))
		if err := v.Verify(msg); err != nil {
			t.Fatal(err)
		}
		if string(msg.Payload) != string(content) {
			t.Fatalf("payload %q", msg.Payload)
		}
	})

	p256 := func(t *testing.T) *ecdsa.PublicKey {
		x := b64u(t, "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
		y := b64u(t, "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}

	// Protected bucket is h'A0' with alg in the unprotected bucket.
	t.Run("sign1-tests/sign-pass-01", func(t *testing.T) {
		msg, err := UnmarshalSign1(hx(t, "D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F"))
		if err != nil {
			t.Fatal(err)
		}
		v, _ := NewVerifier(p256(t))
		if err := v.Verify(msg); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sign1-tests/sign-pass-02", func(t *testing.T) {
		msg, err := UnmarshalSign1(hx(t, "D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B"))
		if err != nil {
			t.Fatal(err)
		}
		v, _ := NewVerifier(p256(t), WithVerifierExternalData(hx(t, "11aa22bb33cc44dd55006699")))
		if err := v.Verify(msg); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("mac0-tests/HMac-01", func(t *testing.T) {
		msg, err := UnmarshalMac0(hx(t, "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58"))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyMAC0(msg, b64u(t, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"), AlgHMAC256); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("aes-gcm-examples/aes-gcm-enc-01", func(t *testing.T) {
		msg, err := UnmarshalEncrypt0(hx(t, "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A"))
		if err != nil {
			t.Fatal(err)
		}
		iv, _ := msg.Unprotected.Get(int64(5)).([]byte)
		pt, err := DecryptEncrypt0(msg, b64u(t, "hJtXIZ2uSN5kbQfbtTNWbg"), iv, AlgA128GCM)
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != string(content) {
			t.Fatalf("plaintext %q", pt)
		}
	})
}

// H5: header labels must be int or tstr.
func TestUnmarshalBstrLabel(t *testing.T) {
	bad := map[string]string{
		"sign1 bstr label (unprotected)": "d28440a1410101f640",        // 18([h'', {h'01': 1}, null, h''])
		"sign1 bstr label (protected)":   "d28444a1410101a0f640",      // protected {h'01': 1}
		"sign1 array label":              "d28440a1820102" + "01f640", // {[1, 2]: 1}
		"sign1 map label":                "d28440a1a1010201f640",      // {{1: 2}: 1}
		"sign1 uint label > int64":       "d28440a11bffffffffffffffff01f640",
		"sign1 negint label < int64":     "d28440a13bffffffffffffffff01f640",
		"mac0 bstr label":                "d18440a1410101f640",
		"encrypt0 bstr label":            "d08340a1410101" + "40",
	}
	for name, h := range bad {
		t.Run(name, func(t *testing.T) {
			data := hx(t, h)
			var err error
			switch data[0] {
			case 0xd2:
				_, err = UnmarshalSign1(data)
			case 0xd1:
				_, err = UnmarshalMac0(data)
			case 0xd0:
				_, err = UnmarshalEncrypt0(data)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// H6: VerifyMulti fails closed.
func TestVerifyMultiFailClosed(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	s1, _ := NewSigner(hardEdPriv)
	s2, _ := NewSigner(other)
	msg, err := SignMulti(hardBody, []*Signer{s1, s2})
	if err != nil {
		t.Fatal(err)
	}
	_, unrelated, _ := ed25519.GenerateKey(rand.Reader)
	vUnrelated, _ := NewVerifier(unrelated.Public())
	vFirst, _ := NewVerifier(hardEdPub)

	if idx, err := VerifyMulti(msg, []*Verifier{vUnrelated}); !errors.Is(err, ErrVerification) || len(idx) != 0 {
		t.Fatalf("no match: idx=%v err=%v, want ErrVerification", idx, err)
	}
	if idx, err := VerifyMulti(msg, []*Verifier{vFirst}); err != nil || len(idx) != 1 || idx[0] != 0 {
		t.Fatalf("RequireAny: idx=%v err=%v", idx, err)
	}
	if idx, err := VerifyMulti(msg, []*Verifier{vFirst}, RequireAll); !errors.Is(err, ErrVerification) || len(idx) != 1 {
		t.Fatalf("RequireAll partial: idx=%v err=%v", idx, err)
	}
	vSecond, _ := NewVerifier(other.Public())
	if idx, err := VerifyMulti(msg, []*Verifier{vFirst, vSecond}, RequireAll); err != nil || len(idx) != 2 {
		t.Fatalf("RequireAll full: idx=%v err=%v", idx, err)
	}
	empty := &Sign{Payload: hardBody}
	if _, err := VerifyMulti(empty, []*Verifier{vFirst}, RequireAll); !errors.Is(err, ErrVerification) {
		t.Fatalf("zero signatures under RequireAll: err=%v", err)
	}
}

// H8: PBES2 iteration count from the header is bounded.
func TestPBES2CountBound(t *testing.T) {
	salt := []byte("0123456789abcdef")
	for _, count := range []int64{0, -1, 1_000_001, 1 << 40} {
		var h Headers
		h.Set(headerLabelSalt, salt)
		h.Set(headerLabelPBES2Count, count)
		start := time.Now()
		_, err := (&PBES2Key{Password: []byte("pw")}).UnwrapKey(make([]byte, 24), h, KeyUnwrapOpts{})
		if !errors.Is(err, ErrDecryption) {
			t.Fatalf("count %d: err = %v, want ErrDecryption", count, err)
		}
		if d := time.Since(start); d > 50*time.Millisecond {
			t.Fatalf("count %d: rejection took %v; PBKDF2 must not run", count, d)
		}
	}
	// Round trip at the default count, and with a caller-set bound.
	cek := make([]byte, 16)
	k := &PBES2Key{Password: []byte("pw"), Count: 1000}
	wrapped, h, err := k.WrapKey(cek, KeyWrapOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.UnwrapKey(wrapped, h, KeyUnwrapOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&PBES2Key{Password: []byte("pw"), MaxCount: 999}).UnwrapKey(wrapped, h, KeyUnwrapOpts{}); !errors.Is(err, ErrDecryption) {
		t.Fatalf("MaxCount 999: err = %v", err)
	}
	if _, err := (&PBES2Key{Password: []byte("pw"), MaxCount: -1}).UnwrapKey(wrapped, h, KeyUnwrapOpts{}); err != nil {
		t.Fatalf("MaxCount -1: %v", err)
	}
}

// badDERSigner is a P-256 crypto.Signer that returns a fixed signature,
// standing in for a misbehaving KMS or HSM.
type badDERSigner struct {
	pub crypto.PublicKey
	der []byte
}

func (b badDERSigner) Public() crypto.PublicKey { return b.pub }
func (b badDERSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return b.der, nil
}

func TestDERToRawOversize(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := func(r, s *big.Int) []byte {
		b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	big33 := new(big.Int).Lsh(big.NewInt(1), 8*33-1) // 33 bytes
	one := big.NewInt(1)
	good := der(one, one)
	cases := map[string][]byte{
		"oversize R":     der(big33, one),
		"oversize S":     der(one, big33),
		"trailing bytes": append(append([]byte{}, good...), 0x00),
		"zero R":         der(big.NewInt(0), one),
		"negative S":     der(one, big.NewInt(-1)),
		"not DER":        {0x01, 0x02},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := NewSigner(badDERSigner{pub: key.Public(), der: d})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Sign(hardBody); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("err = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestHashDataUnsupported(t *testing.T) {
	if _, err := hashData(crypto.MD5, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v", err)
	}
}

// H11: nil payload means detached.
func TestVerifyDetachedMissing(t *testing.T) {
	s, _ := NewSigner(hardEdPriv)
	v, _ := NewVerifier(hardEdPub)
	msg, err := s.Sign(hardBody)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := MarshalSign1(&Sign1{Protected: msg.Protected, Signature: msg.Signature})
	detached, err := UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(detached); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("Verify(detached) = %v, want ErrMissingPayload", err)
	}
	if err := v.VerifyDetached(detached, hardBody); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	if err := v.VerifyDetached(detached, []byte("other")); !errors.Is(err, ErrVerification) {
		t.Fatalf("VerifyDetached(wrong payload) = %v", err)
	}

	// Mac0 and the multi-party verifiers apply the same rule.
	mac, _ := ComputeMAC0(hardBody, hardMACKey, AlgHMAC256)
	mac.Payload = nil
	if err := VerifyMAC0(mac, hardMACKey, AlgHMAC256); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("VerifyMAC0(detached) = %v", err)
	}
	sm, _ := SignMulti(hardBody, []*Signer{s})
	sm.Payload = nil
	if _, err := VerifyMulti(sm, []*Verifier{v}); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("VerifyMulti(detached) = %v", err)
	}
	if err := VerifyMACMulti(&Mac{Recipients: []Recipient{{}}}, &DirectKey{Key: hardMACKey}, 0); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("VerifyMACMulti(detached) = %v", err)
	}
}

// A message whose payload is an empty, attached bstr still verifies.
func TestVerifyEmptyPayload(t *testing.T) {
	s, _ := NewSigner(hardEdPriv)
	v, _ := NewVerifier(hardEdPub)
	msg, err := s.Sign([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Payload == nil {
		t.Fatal("decoded h'' payload must be non-nil")
	}
	if err := v.Verify(got); err != nil {
		t.Fatal(err)
	}
}

func TestECDHNilKeys(t *testing.T) {
	opts := KeyWrapOpts{CEKAlgorithm: AlgA128GCM}
	k := &ECDHESKey{}
	if _, _, err := k.AgreeKey(opts); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("AgreeKey: %v", err)
	}
	if _, _, err := (&ECDHESKey{Alg: AlgECDH_ES_A128KW}).WrapKey(nil, opts); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("WrapKey: %v", err)
	}
	if _, _, err := k.DeriveKey(opts); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("DeriveKey: %v", err)
	}
	var h Headers
	h.Set(headerLabelEphemeralKey, []byte{1})
	if _, err := k.UnwrapKey(nil, h, KeyUnwrapOpts{CEKAlgorithm: AlgA128GCM}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("UnwrapKey: %v", err)
	}
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	k = &ECDHESKey{PrivateKey: priv}
	// A raw-point ephemeral key is the v0.2 encoding (proposal 029):
	// refused by default, and a bad point under WithLegacyECDHES.
	if _, err := k.UnwrapKey(nil, h, KeyUnwrapOpts{CEKAlgorithm: AlgA128GCM}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("UnwrapKey(raw ephemeral): %v", err)
	}
	legacy := KeyUnwrapOpts{CEKAlgorithm: AlgA128GCM, legacy: legacyEncoding{ecdh: true}}
	if _, err := k.UnwrapKey(nil, h, legacy); !errors.Is(err, ErrDecryption) {
		t.Fatalf("UnwrapKey(bad legacy ephemeral): %v", err)
	}
}

// DecryptMulti takes the IV from the message; a wrong size must not
// reach gcm.Open (which panics).
func TestDecryptMultiBadIV(t *testing.T) {
	A, B := corecbor.MakeArray, corecbor.Bytes
	prot := foreignProtected(int64(AlgA128GCM))
	direct := A(B(nil), corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.NegInt(5)}), B(nil))
	for _, iv := range [][]byte{nil, {1}, make([]byte, 13)} {
		ivMap := corecbor.MakeMap(corecbor.MapEntry{Key: corecbor.Uint(5), Value: B(iv)})
		msg, err := UnmarshalEncrypt(encodeCBOR(t, corecbor.MakeTag(96, A(B(prot), ivMap, B(make([]byte, 32)), A(direct)))))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecryptMulti(msg, &DirectKey{Key: hardAESKey}, 0); !errors.Is(err, ErrDecryption) {
			t.Fatalf("iv len %d: err = %v", len(iv), err)
		}
	}
}

// H10 (partial, via H1): verifying one decoded message from many
// goroutines is race-free now that encodeProtected doesn't write.
// Run with -race.
func TestConcurrentVerify(t *testing.T) {
	s, _ := NewSigner(hardEdPriv)
	msg, _ := s.Sign(hardBody)
	msg.Protected.SetKeyID([]byte("kid")) // locally built: re-encoded per call
	data, _ := MarshalSign1(msg)
	decoded, err := UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := NewVerifier(hardEdPub)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				_ = v.Verify(msg) // signature covers only alg; outcome irrelevant here
				_ = v.Verify(decoded)
			}
		})
	}
	wg.Wait()
}
