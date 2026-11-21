// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// exampleKey returns a fixed Ed25519 key so the examples are
// reproducible. Never derive real keys from a constant seed.
func exampleKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

// An attached payload travels inside the COSE_Sign1 message.
func ExampleSigner_Sign() {
	key := exampleKey(1)
	signer, _ := cose.NewSigner(key)
	verifier, _ := cose.NewVerifier(key.Public())

	msg, _ := signer.Sign([]byte("hello"))
	wire, _ := cose.MarshalSign1(msg)

	received, _ := cose.UnmarshalSign1(wire)
	fmt.Println("payload:", string(received.Payload))
	fmt.Println("verify:", verifier.Verify(received))
	// Output:
	// payload: hello
	// verify: <nil>
}

// A detached payload (RFC 9052 §2) is signed but carried separately:
// sign the content, then set Payload to nil before marshaling. On the
// wire the payload is CBOR null, and the receiver supplies the content
// to VerifyDetached. Verify refuses a detached message with
// ErrMissingPayload instead of silently checking it against nothing.
func ExampleVerifier_VerifyDetached() {
	key := exampleKey(2)
	signer, _ := cose.NewSigner(key)
	verifier, _ := cose.NewVerifier(key.Public())

	content := []byte("large artifact, shipped separately")
	msg, _ := signer.Sign(content)
	msg.Payload = nil // detach
	wire, _ := cose.MarshalSign1(msg)

	received, _ := cose.UnmarshalSign1(wire)
	fmt.Println("detached:", received.Payload == nil)
	fmt.Println("Verify:", errors.Is(verifier.Verify(received), cose.ErrMissingPayload))
	fmt.Println("VerifyDetached:", verifier.VerifyDetached(received, content))
	fmt.Println("wrong content fails:", verifier.VerifyDetached(received, []byte("tampered")) != nil)
	// Output:
	// detached: true
	// Verify: true
	// VerifyDetached: <nil>
	// wrong content fails: true
}

// nil and empty are different payloads: nil means detached, while an
// empty, non-nil slice is an attached zero-length payload that Verify
// checks directly.
func ExampleSigner_Sign_emptyPayload() {
	key := exampleKey(3)
	signer, _ := cose.NewSigner(key)
	verifier, _ := cose.NewVerifier(key.Public())

	empty, _ := signer.Sign([]byte{})
	wire, _ := cose.MarshalSign1(empty)
	received, _ := cose.UnmarshalSign1(wire)
	fmt.Println("attached empty:", received.Payload != nil && len(received.Payload) == 0)
	fmt.Println("Verify:", verifier.Verify(received))

	detached, _ := signer.Sign(nil)
	fmt.Println("Sign(nil) is detached:", detached.Payload == nil)
	fmt.Println("Verify:", errors.Is(verifier.Verify(detached), cose.ErrMissingPayload))
	// Output:
	// attached empty: true
	// Verify: <nil>
	// Sign(nil) is detached: true
	// Verify: true
}

// VerifyMulti fails closed: it returns ErrVerification unless the
// policy is met. RequireAny (the default) needs one valid signature;
// RequireAll needs every signature to verify.
func ExampleVerifyMulti() {
	alice, bob := exampleKey(4), exampleKey(5)
	sa, _ := cose.NewSigner(alice)
	sb, _ := cose.NewSigner(bob)
	msg, _ := cose.SignMulti([]byte("release v1"), []*cose.Signer{sa, sb})

	va, _ := cose.NewVerifier(alice.Public())
	vb, _ := cose.NewVerifier(bob.Public())
	stranger, _ := cose.NewVerifier(exampleKey(6).Public())

	idx, err := cose.VerifyMulti(msg, []*cose.Verifier{va})
	fmt.Println("any, alice only:", idx, err)

	_, err = cose.VerifyMulti(msg, []*cose.Verifier{va}, cose.RequireAll)
	fmt.Println("all, alice only:", errors.Is(err, cose.ErrVerification))

	idx, err = cose.VerifyMulti(msg, []*cose.Verifier{va, vb}, cose.RequireAll)
	fmt.Println("all, both:", idx, err)

	_, err = cose.VerifyMulti(msg, []*cose.Verifier{stranger})
	fmt.Println("stranger:", errors.Is(err, cose.ErrVerification))
	// Output:
	// any, alice only: [0] <nil>
	// all, alice only: true
	// all, both: [0 1] <nil>
	// stranger: true
}
