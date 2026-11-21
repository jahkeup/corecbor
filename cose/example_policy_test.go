// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// The message's alg header must match the verifier's key, and
// WithAllowedAlgorithms narrows what is accepted further: a verifier
// that only accepts ES256 rejects an EdDSA message even when the
// signature is valid.
func ExampleWithAllowedAlgorithms() {
	key := exampleKey(7)
	signer, _ := cose.NewSigner(key)
	msg, _ := signer.Sign([]byte("hello"))

	strict, _ := cose.NewVerifier(key.Public(), cose.WithAllowedAlgorithms(cose.AlgES256))
	err := strict.Verify(msg)
	fmt.Println("ES256 only:", errors.Is(err, cose.ErrAlgorithmMismatch))

	ok, _ := cose.NewVerifier(key.Public(), cose.WithAllowedAlgorithms(cose.AlgEdDSA))
	fmt.Println("EdDSA allowed:", ok.Verify(msg))
	// Output:
	// ES256 only: true
	// EdDSA allowed: <nil>
}

// A crit header (RFC 9052 §3.1) lists protected labels the recipient
// must understand. This message, from RFC 9052 Appendix C.1.3, marks
// the text label "reserved" critical, so it only verifies once the
// caller declares that it processes "reserved".
func ExampleWithKnownCriticalHeaders() {
	data, _ := hex.DecodeString("d86284" +
		"56a2687265736572766564f40281687265736572766564" + // {"reserved": false, crit: ["reserved"]}
		"a0" +
		"54546869732069732074686520636f6e74656e742e" + // 'This is the content.'
		"818343a10126a1044231315840" +
		"3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5f" +
		"f3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c")
	msg, _ := cose.UnmarshalSign(data)

	x, _ := base64.RawURLEncoding.DecodeString("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
	y, _ := base64.RawURLEncoding.DecodeString("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
	pub, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))

	plain, _ := cose.NewVerifier(pub)
	_, err := cose.VerifyMulti(msg, []*cose.Verifier{plain})
	fmt.Println("undeclared:", errors.Is(err, cose.ErrCriticalHeader))

	aware, _ := cose.NewVerifier(pub, cose.WithKnownCriticalHeaders("reserved"))
	idx, err := cose.VerifyMulti(msg, []*cose.Verifier{aware})
	fmt.Println("declared:", idx, err)
	// Output:
	// undeclared: true
	// declared: [0] <nil>
}
