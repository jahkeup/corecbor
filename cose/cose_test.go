package cose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/jahkeup/corecbor"
)

func TestSign1_Ed25519_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello COSE")
	msg, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Verify(msg2); err != nil {
		t.Fatal("verify failed:", err)
	}
}

func TestSign1_ES256_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello ES256")
	msg, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Verify(msg2); err != nil {
		t.Fatal("verify failed:", err)
	}
}

func TestSign1_ES384_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello ES384")
	msg, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Verify(msg2); err != nil {
		t.Fatal("verify failed:", err)
	}
}

func TestSign1_Verify_WrongKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	signer, _ := NewSigner(priv1)
	msg, _ := signer.Sign([]byte("test"))

	verifier, _ := NewVerifier(pub2)
	err := verifier.Verify(msg)
	if err != ErrVerification {
		t.Fatalf("expected ErrVerification, got %v", err)
	}
}

func TestSign1_Verify_TamperedPayload(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	signer, _ := NewSigner(priv)
	msg, _ := signer.Sign([]byte("original"))

	msg.Payload = []byte("tampered")

	verifier, _ := NewVerifier(pub)
	err := verifier.Verify(msg)
	if err != ErrVerification {
		t.Fatalf("expected ErrVerification, got %v", err)
	}
}

func TestSign1_DetachedPayload(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	signer, _ := NewSigner(priv)
	payload := []byte("detached content")
	msg, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Detach payload
	msg.Payload = nil

	data, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := UnmarshalSign1(data)
	if err != nil {
		t.Fatal(err)
	}

	// Reattach for verification
	msg2.Payload = payload

	verifier, _ := NewVerifier(pub)
	if err := verifier.Verify(msg2); err != nil {
		t.Fatal("verify with reattached payload failed:", err)
	}
}

func TestMarshalSign1_Tagged(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewSigner(priv)
	msg, _ := signer.Sign([]byte("tagged"))

	data, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}

	// CBOR tag 18: major type 6 (0xc0) with value 18 = 0xd2
	if len(data) == 0 || data[0] != 0xd2 {
		t.Fatalf("expected CBOR tag 18 (0xd2), got first byte 0x%02x", data[0])
	}
}

func TestUnmarshalSign1_Untagged(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewSigner(priv)
	msg, _ := signer.Sign([]byte("untagged"))

	data, err := MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Strip the tag prefix (0xd2) to get untagged array
	// Tag 18 is encoded as single byte 0xd2 (major 6, additional 18)
	untagged := data[1:]

	msg2, err := UnmarshalSign1(untagged)
	if err != nil {
		t.Fatal("unmarshal untagged failed:", err)
	}

	if !bytes.Equal(msg2.Payload, []byte("untagged")) {
		t.Fatal("payload mismatch")
	}
}

func TestKeyConversion_Ed25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	coseKey, err := NewKeyFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	if coseKey.KeyType() != KeyTypeOKP {
		t.Fatalf("expected OKP key type, got %d", coseKey.KeyType())
	}
	if coseKey.Curve() != CurveEd25519 {
		t.Fatalf("expected Ed25519 curve, got %d", coseKey.Curve())
	}

	recoveredPub, err := coseKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	if !pub.Equal(recoveredPub) {
		t.Fatal("public keys don't match")
	}

	recoveredSigner, err := coseKey.Signer()
	if err != nil {
		t.Fatal(err)
	}

	// Sign with recovered key and verify with original
	signer, _ := NewSigner(recoveredSigner)
	msg, _ := signer.Sign([]byte("roundtrip"))
	verifier, _ := NewVerifier(pub)
	if err := verifier.Verify(msg); err != nil {
		t.Fatal("verify with round-tripped key failed:", err)
	}
}

func TestKeyConversion_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	coseKey, err := NewKeyFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	if coseKey.KeyType() != KeyTypeEC2 {
		t.Fatalf("expected EC2 key type, got %d", coseKey.KeyType())
	}
	if coseKey.Curve() != CurveP256 {
		t.Fatalf("expected P256 curve, got %d", coseKey.Curve())
	}

	recoveredPub, err := coseKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	ecPub := recoveredPub.(*ecdsa.PublicKey)
	if !priv.PublicKey.Equal(ecPub) {
		t.Fatal("public keys don't match")
	}

	recoveredSigner, err := coseKey.Signer()
	if err != nil {
		t.Fatal(err)
	}

	signer, _ := NewSigner(recoveredSigner)
	msg, _ := signer.Sign([]byte("p256 roundtrip"))
	verifier, _ := NewVerifier(&priv.PublicKey)
	if err := verifier.Verify(msg); err != nil {
		t.Fatal("verify with round-tripped key failed:", err)
	}
}

func TestSigStructure_Deterministic(t *testing.T) {
	protected := []byte{0xa1, 0x01, 0x27} // {1: -8} in CBOR
	external := []byte{}
	payload := []byte("test payload")

	enc := corecbor.New(corecbor.ModeCoreDeterministic)

	sig1 := buildSigStructure(protected, external, payload)
	data1, err := enc.Encode(nil, sig1)
	if err != nil {
		t.Fatal(err)
	}

	sig2 := buildSigStructure(protected, external, payload)
	data2, err := enc.Encode(nil, sig2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data1, data2) {
		t.Fatal("sig_structure encoding is not deterministic")
	}
}
