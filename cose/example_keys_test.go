// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
)

// SignDetached signs content that travels separately; the receiver
// supplies it to VerifyDetached.
func ExampleSigner_SignDetached() {
	key := exampleKey(20)
	signer, _ := cose.NewSigner(key)
	verifier, _ := cose.NewVerifier(key.Public())

	content := []byte("release-1.0.tar.gz bytes")
	msg, _ := signer.SignDetached(content)
	wire, _ := cose.MarshalSign1(msg)

	received, _ := cose.UnmarshalSign1(wire)
	fmt.Println("payload on the wire:", received.Payload == nil)
	fmt.Println("VerifyDetached:", verifier.VerifyDetached(received, content))
	// Output:
	// payload on the wire: true
	// VerifyDetached: <nil>
}

// Protected headers carry a kid and CWT Claims (RFC 9597), as signed
// statements do. The Signer sets alg itself.
func ExampleWithProtectedHeaders() {
	key := exampleKey(21)
	var prot cose.Headers
	prot.SetKeyID([]byte("issuer-key-1"))
	_ = prot.SetType("application/example+cose")
	_ = prot.SetCWTClaims(corecbor.MakeMap(
		corecbor.MapEntry{Key: corecbor.Uint(1), Value: corecbor.Text("https://issuer.example")}, // iss
		corecbor.MapEntry{Key: corecbor.Uint(2), Value: corecbor.Text("subject-1")},              // sub
	))
	signer, _ := cose.NewSigner(key, cose.WithProtectedHeaders(prot))

	msg, _ := signer.Sign([]byte("statement"))
	wire, _ := cose.MarshalSign1(msg)
	received, _ := cose.UnmarshalSign1(wire)

	claims, _ := received.Protected.CWTClaims()
	_, typ, _ := received.Protected.Type()
	fmt.Printf("kid=%s alg=%s typ=%s\n", received.Protected.KeyID(), received.Protected.Algorithm(), typ)
	fmt.Println("iss:", claims.Map()[0].Value.TextVal())
	// Output:
	// kid=issuer-key-1 alg=EdDSA typ=application/example+cose
	// iss: https://issuer.example
}

// ParseKeyPrefix reads a COSE_Key from the front of a buffer and returns
// what follows, as in WebAuthn attested credential data with extensions.
func ExampleParseKeyPrefix() {
	// COSE_Key (EC2, P-256, ES256) from the W3C WebAuthn L3 packed ES256
	// test vector, followed by an extensions map {"credProtect": 2}.
	data, _ := hex.DecodeString("a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423" +
		"a16b6372656450726f7465637402")
	key, rest, err := cose.ParseKeyPrefix(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	alg, _ := key.Algorithm()
	fmt.Println("kty:", key.KeyType(), "alg:", alg)
	fmt.Printf("extensions: %x\n", rest)
	// Output:
	// kty: 2 alg: ES256
	// extensions: a16b6372656450726f7465637402
}

// A KeySet resolves verification keys by kid; VerifySign1 checks each
// candidate under the key's own alg and key_ops.
func ExampleKeySetResolver() {
	alice, bob := exampleKey(22), exampleKey(23)
	ka, _ := cose.NewKeyFromPublic(alice.Public())
	ka.SetID([]byte("alice"))
	kb, _ := cose.NewKeyFromPublic(bob.Public())
	kb.SetID([]byte("bob"))
	keys := cose.KeySet{ka, kb}

	var h cose.Headers
	h.SetKeyID([]byte("bob"))
	signer, _ := cose.NewSigner(bob, cose.WithProtectedHeaders(h))
	msg, _ := signer.Sign([]byte("hello"))

	fmt.Println("lookup bob:", len(keys.Lookup([]byte("bob"), 0, cose.KeyOpVerify)))
	fmt.Println("VerifySign1:", cose.VerifySign1(context.Background(), msg, cose.KeySetResolver(keys)))

	var other cose.Headers
	other.SetKeyID([]byte("carol"))
	stranger, _ := cose.NewSigner(exampleKey(24), cose.WithProtectedHeaders(other))
	bad, _ := stranger.Sign([]byte("hello"))
	err := cose.VerifySign1(context.Background(), bad, cose.KeySetResolver(keys))
	fmt.Println("unknown kid:", errors.Is(err, cose.ErrVerification))
	// Output:
	// lookup bob: 1
	// VerifySign1: <nil>
	// unknown kid: true
}

// Thumbprint computes the RFC 9679 COSE Key Thumbprint, here for the
// RFC's own example key.
func ExampleKey_Thumbprint() {
	data, _ := hex.DecodeString("a50102200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c025820496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec")
	key, _ := cose.ParseKey(data)
	tp, _ := key.Thumbprint(crypto.SHA256)
	fmt.Printf("%x\n", tp)
	// Output:
	// 496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec
}
