package edhoc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

func TestMessage4_KeyConfirmation(t *testing.T) {
	iPub, iPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	initiator, err := NewInitiator(InitiatorConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   iPriv,
		PeerPublic:   rPub,
		ConnectionID: []byte{0x10},
	})
	if err != nil {
		t.Fatal(err)
	}

	responder, err := NewResponder(ResponderConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x11},
	})
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := initiator.CreateMessage1()
	if err != nil {
		t.Fatalf("CreateMessage1: %v", err)
	}

	msg2, err := responder.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}

	msg3, err := initiator.ProcessMessage2(msg2)
	if err != nil {
		t.Fatalf("ProcessMessage2: %v", err)
	}

	if err := responder.ProcessMessage3(msg3); err != nil {
		t.Fatalf("ProcessMessage3: %v", err)
	}

	msg4, err := responder.CreateMessage4()
	if err != nil {
		t.Fatalf("CreateMessage4: %v", err)
	}
	t.Logf("Message 4: %d bytes", len(msg4))

	if err := initiator.ProcessMessage4(msg4); err != nil {
		t.Fatalf("ProcessMessage4: %v", err)
	}
}

func TestMessage4_BeforeComplete(t *testing.T) {
	_, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	iPub, _, _ := ed25519.GenerateKey(rand.Reader)

	responder, _ := NewResponder(ResponderConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x02},
	})

	_, err := responder.CreateMessage4()
	if !errors.Is(err, ErrStateViolation) {
		t.Fatalf("expected ErrStateViolation, got: %v", err)
	}
}

func TestMessage4_Tampered(t *testing.T) {
	iPub, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)

	initiator, _ := NewInitiator(InitiatorConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   iPriv,
		PeerPublic:   rPub,
		ConnectionID: []byte{0x10},
	})
	responder, _ := NewResponder(ResponderConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x11},
	})

	msg1, _ := initiator.CreateMessage1()
	msg2, _ := responder.ProcessMessage1(msg1)
	msg3, _ := initiator.ProcessMessage2(msg2)
	_ = responder.ProcessMessage3(msg3)

	msg4, _ := responder.CreateMessage4()
	msg4[len(msg4)-1] ^= 0xFF

	err := initiator.ProcessMessage4(msg4)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication for tampered msg4, got: %v", err)
	}
}

func TestExporter_BothSidesMatch(t *testing.T) {
	iPub, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)

	initiator, _ := NewInitiator(InitiatorConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   iPriv,
		PeerPublic:   rPub,
		ConnectionID: []byte{0x20},
	})
	responder, _ := NewResponder(ResponderConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x21},
	})

	msg1, _ := initiator.CreateMessage1()
	msg2, _ := responder.ProcessMessage1(msg1)
	msg3, _ := initiator.ProcessMessage2(msg2)
	_ = responder.ProcessMessage3(msg3)

	iOut, err := initiator.Export(0, []byte("test-context"), 32)
	if err != nil {
		t.Fatalf("Initiator Export: %v", err)
	}

	rOut, err := responder.Export(0, []byte("test-context"), 32)
	if err != nil {
		t.Fatalf("Responder Export: %v", err)
	}

	if !bytes.Equal(iOut, rOut) {
		t.Fatalf("Export mismatch:\n  initiator: %x\n  responder: %x", iOut, rOut)
	}
	t.Logf("Exported key: %x", iOut)
}

func TestExporter_DifferentLabels(t *testing.T) {
	iPub, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)

	initiator, _ := NewInitiator(InitiatorConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   iPriv,
		PeerPublic:   rPub,
		ConnectionID: []byte{0x30},
	})
	responder, _ := NewResponder(ResponderConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x31},
	})

	msg1, _ := initiator.CreateMessage1()
	msg2, _ := responder.ProcessMessage1(msg1)
	msg3, _ := initiator.ProcessMessage2(msg2)
	_ = responder.ProcessMessage3(msg3)

	out1, err := initiator.Export(1, []byte("ctx"), 16)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := initiator.Export(2, []byte("ctx"), 16)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(out1, out2) {
		t.Fatal("different labels should produce different output")
	}
}

func TestExporter_BeforeComplete(t *testing.T) {
	_, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, _, _ := ed25519.GenerateKey(rand.Reader)

	initiator, _ := NewInitiator(InitiatorConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   iPriv,
		PeerPublic:   rPub,
		ConnectionID: []byte{0x40},
	})

	_, err := initiator.Export(0, nil, 16)
	if !errors.Is(err, ErrStateViolation) {
		t.Fatalf("expected ErrStateViolation, got: %v", err)
	}

	_, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	iPub, _, _ := ed25519.GenerateKey(rand.Reader)

	responder, _ := NewResponder(ResponderConfig{
		Suites:       []CipherSuite{Suite0},
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x41},
	})

	_, err = responder.Export(0, nil, 16)
	if !errors.Is(err, ErrStateViolation) {
		t.Fatalf("expected ErrStateViolation, got: %v", err)
	}
}

func TestCWTCredential_RoundTrip(t *testing.T) {
	iPub, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)

	iCWT := createTestCWT(t, iPriv, iPub)
	rCWT := createTestCWT(t, rPriv, rPub)

	initiator, err := NewInitiator(InitiatorConfig{
		Suites:     []CipherSuite{Suite0},
		PrivateKey: iPriv,
		PeerPublic: rPub,
		Credential: &Credential{
			Type:     CredentialCWT,
			CWTBytes: iCWT,
		},
		PeerCredential: &Credential{
			Type:     CredentialCWT,
			CWTBytes: rCWT,
		},
		CWTIssuerKey: rPub,
		ConnectionID: []byte{0x50},
	})
	if err != nil {
		t.Fatal(err)
	}

	responder, err := NewResponder(ResponderConfig{
		Suites:     []CipherSuite{Suite0},
		PrivateKey: rPriv,
		PeerPublic: iPub,
		Credential: &Credential{
			Type:     CredentialCWT,
			CWTBytes: rCWT,
		},
		PeerCredential: &Credential{
			Type:     CredentialCWT,
			CWTBytes: iCWT,
		},
		CWTIssuerKey: iPub,
		ConnectionID: []byte{0x51},
	})
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := initiator.CreateMessage1()
	if err != nil {
		t.Fatalf("CreateMessage1: %v", err)
	}

	msg2, err := responder.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}

	msg3, err := initiator.ProcessMessage2(msg2)
	if err != nil {
		t.Fatalf("ProcessMessage2: %v", err)
	}

	if err := responder.ProcessMessage3(msg3); err != nil {
		t.Fatalf("ProcessMessage3: %v", err)
	}

	iCtx, err := initiator.ExportOSCORE()
	if err != nil {
		t.Fatal(err)
	}
	rCtx, err := responder.ExportOSCORE()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(iCtx.MasterSecret, rCtx.MasterSecret) {
		t.Fatal("Master Secret mismatch with CWT credentials")
	}
	t.Logf("CWT credential handshake succeeded, Master Secret: %x", iCtx.MasterSecret)
}

func createTestCWT(t *testing.T, signerKey ed25519.PrivateKey, subjectPub ed25519.PublicKey) []byte {
	t.Helper()

	coseKeyObj, err := cose.NewKeyFromPublic(ed25519.PublicKey(subjectPub))
	if err != nil {
		t.Fatalf("creating COSE key: %v", err)
	}

	claims := &cwt.ClaimsSet{
		Subject: "edhoc-peer",
		Confirmation: &cwt.Confirmation{
			Key: coseKeyObj,
		},
	}

	signer, err := cose.NewSigner(signerKey)
	if err != nil {
		t.Fatalf("creating COSE signer: %v", err)
	}

	cwtBytes, err := cwt.Sign(claims, signer)
	if err != nil {
		t.Fatalf("signing CWT: %v", err)
	}

	return cwtBytes
}
