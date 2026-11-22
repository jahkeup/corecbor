// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// TestGoldenV022 enforces proposal 034 for the cose module. Only
// deterministic operations are recorded (Ed25519, HMAC, AES-GCM with a
// fixed nonce); ECDSA signatures are randomized and excluded.
func TestGoldenV022(t *testing.T) {
	g.Check(t, "testdata/golden/v0.2.2/cose.json", coseGoldenCases(), goldenChanges)
}

var coseSentinels = []g.Sentinel{
	{Name: "ErrVerification", Err: cose.ErrVerification},
	{Name: "ErrInvalidKey", Err: cose.ErrInvalidKey},
	{Name: "ErrUnsupportedAlgorithm", Err: cose.ErrUnsupportedAlgorithm},
	{Name: "ErrMalformed", Err: cose.ErrMalformed},
	{Name: "ErrDecryption", Err: cose.ErrDecryption},
	{Name: "ErrMACVerification", Err: cose.ErrMACVerification},
	{Name: "ErrTruncated", Err: corecbor.ErrTruncated},
	{Name: "ErrTrailingBytes", Err: corecbor.ErrTrailingBytes},
}

func hexOf(b []byte, err error) string { return g.Hex(b, err, coseSentinels) }
func okOf(err error) string            { return g.OK(err, coseSentinels) }

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.SeedSize) }

var (
	edPriv  = ed25519.NewKeyFromSeed(seed(1))
	edPub   = edPriv.Public().(ed25519.PublicKey)
	edPriv2 = ed25519.NewKeyFromSeed(seed(2))
	edPub2  = edPriv2.Public().(ed25519.PublicKey)
	macKey  = bytes.Repeat([]byte{0x0b}, 32)
	macKey2 = bytes.Repeat([]byte{0x0c}, 32)
	aesKey  = bytes.Repeat([]byte{0x0d}, 16)
	aesKey2 = bytes.Repeat([]byte{0x0e}, 32)
	nonce   = bytes.Repeat([]byte{0x0f}, 12)
)

func mustSigner(priv ed25519.PrivateKey, opts ...cose.SignerOption) *cose.Signer {
	s, err := cose.NewSigner(priv, opts...)
	if err != nil {
		panic(err)
	}
	return s
}

func mustVerifier(pub ed25519.PublicKey, opts ...cose.VerifierOption) *cose.Verifier {
	v, err := cose.NewVerifier(pub, opts...)
	if err != nil {
		panic(err)
	}
	return v
}

func signedBytes(payload []byte, opts ...cose.SignerOption) []byte {
	msg, err := mustSigner(edPriv, opts...).Sign(payload)
	if err != nil {
		panic(err)
	}
	b, err := cose.MarshalSign1(msg)
	if err != nil {
		panic(err)
	}
	return b
}

func verifyBytes(data []byte, pub ed25519.PublicKey, opts ...cose.VerifierOption) string {
	msg, err := cose.UnmarshalSign1(data)
	if err != nil {
		return okOf(err)
	}
	return okOf(mustVerifier(pub, opts...).Verify(msg))
}

// unsortedProtectedSign1 builds a COSE_Sign1 whose protected header map is
// not in deterministic order ({4: h'6b', 1: -8}) and signs those exact
// bytes, as a third-party encoder may.
func unsortedProtectedSign1() []byte {
	protected := g.MustHex("a204416b0127")
	payload := []byte("payload")
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	tbs, err := enc.Encode(nil, corecbor.MakeArray(
		corecbor.Text("Signature1"), corecbor.Bytes(protected), corecbor.Bytes(nil), corecbor.Bytes(payload),
	))
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(edPriv, tbs)
	out, err := enc.Encode(nil, corecbor.MakeTag(18, corecbor.MakeArray(
		corecbor.Bytes(protected), corecbor.MakeMap(), corecbor.Bytes(payload), corecbor.Bytes(sig),
	)))
	if err != nil {
		panic(err)
	}
	return out
}

func coseGoldenCases() []g.Case {
	var cases []g.Case
	add := func(id string, run func() string) { cases = append(cases, g.Case{ID: id, Run: run}) }

	// Sign1 / Ed25519.
	add("cose/sign1/ed25519", func() string { return "hex:" + fmt.Sprintf("%x", signedBytes([]byte("payload"))) })
	add("cose/sign1/ed25519-empty-payload", func() string { return "hex:" + fmt.Sprintf("%x", signedBytes(nil)) })
	add("cose/sign1/ed25519-external-data", func() string {
		return "hex:" + fmt.Sprintf("%x", signedBytes([]byte("payload"), cose.WithSignerExternalData([]byte("aad"))))
	})
	add("cose/sign1/verify-ok", func() string { return verifyBytes(signedBytes([]byte("payload")), edPub) })
	add("cose/sign1/verify-wrong-key", func() string { return verifyBytes(signedBytes([]byte("payload")), edPub2) })
	add("cose/sign1/verify-tampered-payload", func() string {
		msg, _ := cose.UnmarshalSign1(signedBytes([]byte("payload")))
		msg.Payload = []byte("pAyload")
		return okOf(mustVerifier(edPub).Verify(msg))
	})
	add("cose/sign1/verify-external-data-ok", func() string {
		return verifyBytes(signedBytes([]byte("p"), cose.WithSignerExternalData([]byte("aad"))), edPub, cose.WithVerifierExternalData([]byte("aad")))
	})
	add("cose/sign1/verify-external-data-missing", func() string {
		return verifyBytes(signedBytes([]byte("p"), cose.WithSignerExternalData([]byte("aad"))), edPub)
	})
	add("cose/sign1/verify-nil-payload-after-empty", func() string {
		msg, _ := cose.UnmarshalSign1(signedBytes(nil))
		msg.Payload = nil
		return okOf(mustVerifier(edPub).Verify(msg))
	})
	add("cose/sign1/marshal-detached", func() string {
		msg, _ := mustSigner(edPriv).Sign([]byte("payload"))
		msg.Payload = nil
		return hexOf(cose.MarshalSign1(msg))
	})
	add("cose/sign1/protected-header-getters", func() string {
		msg, err := cose.UnmarshalSign1(signedBytes([]byte("payload")))
		if err != nil {
			return okOf(err)
		}
		return fmt.Sprintf("ok:alg=%d kid=%x empty=%v uempty=%v", msg.Protected.Algorithm(), msg.Protected.KeyID(), msg.Protected.IsEmpty(), msg.Unprotected.IsEmpty())
	})

	// UnmarshalSign1 edge cases.
	add("cose/unmarshal/sign1-untagged", func() string {
		b := signedBytes([]byte("payload"))
		return verifyBytes(b[1:], edPub)
	})
	add("cose/unmarshal/sign1-wrong-tag", func() string {
		b := signedBytes([]byte("payload"))
		b[0] = 0xd1
		_, err := cose.UnmarshalSign1(b)
		return okOf(err)
	})
	add("cose/unmarshal/sign1-short-array", func() string {
		_, err := cose.UnmarshalSign1(g.MustHex("d28340a0f6"))
		return okOf(err)
	})
	add("cose/unmarshal/sign1-garbage", func() string {
		_, err := cose.UnmarshalSign1(g.MustHex("ff"))
		return okOf(err)
	})
	add("cose/unmarshal/sign1-bytes-header-label", func() string {
		_, err := cose.UnmarshalSign1(g.MustHex("d28440a1410101f640"))
		return okOf(err)
	})
	add("cose/verify/protected-unsorted", func() string { return verifyBytes(unsortedProtectedSign1(), edPub) })

	// Headers encoding through MarshalSign1.
	add("cose/headers/set-int64", func() string {
		msg := &cose.Sign1{Payload: []byte("p"), Signature: []byte{1}}
		msg.Protected.SetAlgorithm(cose.AlgEdDSA)
		msg.Protected.SetKeyID([]byte("kid"))
		msg.Unprotected.Set(int64(3), "text/plain")
		return hexOf(cose.MarshalSign1(msg))
	})
	add("cose/headers/set-algorithm-typed", func() string {
		msg := &cose.Sign1{Payload: []byte("p"), Signature: []byte{1}}
		msg.Protected.Set(int64(1), cose.AlgES256)
		return hexOf(cose.MarshalSign1(msg))
	})
	add("cose/headers/set-text-label", func() string {
		msg := &cose.Sign1{Payload: []byte("p"), Signature: []byte{1}}
		msg.Unprotected.Set("custom", []byte{1, 2})
		return hexOf(cose.MarshalSign1(msg))
	})

	// Mac0.
	mac0 := func(payload, key []byte, alg cose.Algorithm, opts ...cose.MACOption) ([]byte, error) {
		msg, err := cose.ComputeMAC0(payload, key, alg, opts...)
		if err != nil {
			return nil, err
		}
		return cose.MarshalMac0(msg)
	}
	verifyMac0 := func(data, key []byte, alg cose.Algorithm, opts ...cose.MACOption) string {
		msg, err := cose.UnmarshalMac0(data)
		if err != nil {
			return okOf(err)
		}
		return okOf(cose.VerifyMAC0(msg, key, alg, opts...))
	}
	must := func(b []byte, err error) []byte {
		if err != nil {
			panic(err)
		}
		return b
	}
	add("cose/mac0/hmac256", func() string { return hexOf(mac0([]byte("payload"), macKey, cose.AlgHMAC256)) })
	add("cose/mac0/hmac256-64", func() string { return hexOf(mac0([]byte("payload"), macKey, cose.AlgHMAC256_64)) })
	add("cose/mac0/hmac384", func() string { return hexOf(mac0([]byte("payload"), bytes.Repeat([]byte{1}, 48), cose.AlgHMAC384)) })
	add("cose/mac0/hmac512", func() string { return hexOf(mac0([]byte("payload"), bytes.Repeat([]byte{1}, 64), cose.AlgHMAC512)) })
	add("cose/mac0/external-aad", func() string {
		return hexOf(mac0([]byte("payload"), macKey, cose.AlgHMAC256, cose.WithMACExternalAAD([]byte("aad"))))
	})
	add("cose/mac0/empty-key", func() string { return hexOf(mac0([]byte("payload"), nil, cose.AlgHMAC256)) })
	add("cose/mac0/short-key", func() string { return hexOf(mac0([]byte("payload"), []byte{1}, cose.AlgHMAC256)) })
	add("cose/mac0/unsupported-alg", func() string { return hexOf(mac0([]byte("payload"), macKey, cose.AlgA128GCM)) })
	add("cose/mac0/verify-ok", func() string {
		return verifyMac0(must(mac0([]byte("payload"), macKey, cose.AlgHMAC256)), macKey, cose.AlgHMAC256)
	})
	add("cose/mac0/verify-wrong-key", func() string {
		return verifyMac0(must(mac0([]byte("payload"), macKey, cose.AlgHMAC256)), macKey2, cose.AlgHMAC256)
	})
	add("cose/mac0/verify-alg-param-mismatch", func() string {
		return verifyMac0(must(mac0([]byte("payload"), macKey, cose.AlgHMAC256)), macKey, cose.AlgHMAC256_64)
	})
	add("cose/mac0/verify-external-aad-missing", func() string {
		return verifyMac0(must(mac0([]byte("payload"), macKey, cose.AlgHMAC256, cose.WithMACExternalAAD([]byte("aad")))), macKey, cose.AlgHMAC256)
	})

	// Encrypt0 with fixed key and nonce.
	enc0 := func(pt, key []byte, alg cose.Algorithm, opts ...cose.EncryptOption) ([]byte, error) {
		msg, err := cose.EncryptEncrypt0(pt, key, nonce, alg, opts...) //nolint:staticcheck // pins the deprecated v0.2.2 API
		if err != nil {
			return nil, err
		}
		return cose.MarshalEncrypt0(msg)
	}
	dec0 := func(data, key, n []byte, alg cose.Algorithm, opts ...cose.EncryptOption) string {
		msg, err := cose.UnmarshalEncrypt0(data)
		if err != nil {
			return okOf(err)
		}
		pt, err := cose.DecryptEncrypt0(msg, key, n, alg, opts...) //nolint:staticcheck // pins the deprecated v0.2.2 API
		return hexOf(pt, err)
	}
	add("cose/encrypt0/a128gcm", func() string { return hexOf(enc0([]byte("secret"), aesKey, cose.AlgA128GCM)) })
	add("cose/encrypt0/a256gcm", func() string { return hexOf(enc0([]byte("secret"), aesKey2, cose.AlgA256GCM)) })
	add("cose/encrypt0/external-aad", func() string {
		return hexOf(enc0([]byte("secret"), aesKey, cose.AlgA128GCM, cose.WithEncryptExternalAAD([]byte("aad"))))
	})
	add("cose/encrypt0/wrong-key-size", func() string { return hexOf(enc0([]byte("secret"), aesKey2, cose.AlgA128GCM)) })
	add("cose/encrypt0/decrypt-ok", func() string {
		return dec0(must(enc0([]byte("secret"), aesKey, cose.AlgA128GCM)), aesKey, nonce, cose.AlgA128GCM)
	})
	add("cose/encrypt0/decrypt-wrong-nonce", func() string {
		return dec0(must(enc0([]byte("secret"), aesKey, cose.AlgA128GCM)), aesKey, bytes.Repeat([]byte{1}, 12), cose.AlgA128GCM)
	})
	add("cose/encrypt0/decrypt-wrong-key", func() string {
		return dec0(must(enc0([]byte("secret"), aesKey, cose.AlgA128GCM)), bytes.Repeat([]byte{1}, 16), nonce, cose.AlgA128GCM)
	})

	// COSE_Key from fixed keys.
	add("cose/key/ed25519-public", func() string {
		k, err := cose.NewKeyFromPublic(edPub)
		if err != nil {
			return okOf(err)
		}
		pub, err := k.PublicKey()
		if err != nil {
			return okOf(err)
		}
		return fmt.Sprintf("ok:kty=%d crv=%d equal=%v", k.KeyType(), k.Curve(), edPub.Equal(pub))
	})
	add("cose/key/ed25519-signer", func() string {
		k, err := cose.NewKeyFromSigner(edPriv)
		if err != nil {
			return okOf(err)
		}
		s, err := k.Signer()
		if err != nil {
			return okOf(err)
		}
		return fmt.Sprintf("ok:kty=%d crv=%d equal=%v", k.KeyType(), k.Curve(), edPub.Equal(s.Public()))
	})
	add("cose/key/p256-public", func() string {
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x11}, 32))
		if err != nil {
			return okOf(err)
		}
		k, err := cose.NewKeyFromPublic(&priv.PublicKey)
		if err != nil {
			return okOf(err)
		}
		pub, err := k.PublicKey()
		if err != nil {
			return okOf(err)
		}
		return fmt.Sprintf("ok:kty=%d crv=%d equal=%v", k.KeyType(), k.Curve(), priv.PublicKey.Equal(pub))
	})
	add("cose/key/unsupported", func() string {
		_, err := cose.NewKeyFromPublic("not a key")
		return okOf(err)
	})

	// Algorithm identifiers and names (exported constants must not change).
	for _, alg := range []cose.Algorithm{
		cose.AlgEdDSA, cose.AlgES256, cose.AlgES384, cose.AlgES512,
		cose.AlgA128GCM, cose.AlgA192GCM, cose.AlgA256GCM,
		cose.AlgHMAC256_64, cose.AlgHMAC256, cose.AlgHMAC384, cose.AlgHMAC512,
		cose.AlgDirect, cose.AlgA128KW, cose.AlgA192KW, cose.AlgA256KW,
		cose.AlgECDH_ES_HKDF_256, cose.AlgPBES2_HS256_A128KW, cose.AlgHPKEBaseP256SHA256AES128GCM,
	} {
		add(fmt.Sprintf("cose/alg/%d", int64(alg)), func() string { return "ok:" + alg.String() })
	}

	// Multi-signer and multi-recipient MAC.
	multi := func() *cose.Sign {
		msg, err := cose.SignMulti([]byte("payload"), []*cose.Signer{mustSigner(edPriv), mustSigner(edPriv2)})
		if err != nil {
			panic(err)
		}
		return msg
	}
	add("cose/multi/sign", func() string { return hexOf(cose.MarshalSign(multi())) })
	add("cose/multi/verify-first", func() string {
		idx, err := cose.VerifyMulti(multi(), []*cose.Verifier{mustVerifier(edPub)})
		return g.Str(fmt.Sprint(idx), err, coseSentinels)
	})
	add("cose/multi/verify-none-match", func() string {
		other := ed25519.NewKeyFromSeed(seed(3)).Public().(ed25519.PublicKey)
		idx, err := cose.VerifyMulti(multi(), []*cose.Verifier{mustVerifier(other)})
		return g.Str(fmt.Sprint(idx), err, coseSentinels)
	})
	add("cose/multi/verify-no-verifiers", func() string {
		idx, err := cose.VerifyMulti(multi(), nil)
		return g.Str(fmt.Sprint(idx), err, coseSentinels)
	})
	add("cose/multi/sign-roundtrip", func() string {
		b, err := cose.MarshalSign(multi())
		if err != nil {
			return okOf(err)
		}
		msg, err := cose.UnmarshalSign(b)
		if err != nil {
			return okOf(err)
		}
		idx, err := cose.VerifyMulti(msg, []*cose.Verifier{mustVerifier(edPub2)})
		return g.Str(fmt.Sprint(idx), err, coseSentinels)
	})
	macMulti := func() (*cose.Mac, error) {
		return cose.ComputeMACMulti([]byte("payload"), macKey, cose.AlgHMAC256, []cose.KeyDeriver{&cose.DirectKey{Key: macKey}})
	}
	add("cose/multi/mac-direct", func() string {
		m, err := macMulti()
		if err != nil {
			return okOf(err)
		}
		return hexOf(cose.MarshalMac(m))
	})
	add("cose/multi/mac-direct-verify", func() string {
		m, err := macMulti()
		if err != nil {
			return okOf(err)
		}
		return okOf(cose.VerifyMACMulti(m, &cose.DirectKey{Key: macKey}, 0))
	})
	add("cose/multi/mac-direct-verify-wrong-key", func() string {
		m, err := macMulti()
		if err != nil {
			return okOf(err)
		}
		return okOf(cose.VerifyMACMulti(m, &cose.DirectKey{Key: macKey2}, 0))
	})
	add("cose/multi/mac-no-recipients", func() string {
		_, err := cose.ComputeMACMulti([]byte("payload"), macKey, cose.AlgHMAC256, nil)
		return okOf(err)
	})
	return cases
}
