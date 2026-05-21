package edhoc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestHandshake_Suite0(t *testing.T) {
	iPub, iPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	initiator, err := NewInitiator(InitiatorConfig{
		Suite:        Suite0,
		PrivateKey:   iPriv,
		PeerPublic:   rPub,
		ConnectionID: []byte{0x01},
	})
	if err != nil {
		t.Fatal(err)
	}

	responder, err := NewResponder(ResponderConfig{
		Suite:        Suite0,
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x02},
	})
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := initiator.CreateMessage1()
	if err != nil {
		t.Fatalf("CreateMessage1: %v", err)
	}
	t.Logf("Message 1: %d bytes", len(msg1))

	msg2, err := responder.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	t.Logf("Message 2: %d bytes", len(msg2))

	msg3, err := initiator.ProcessMessage2(msg2)
	if err != nil {
		t.Fatalf("ProcessMessage2: %v", err)
	}
	t.Logf("Message 3: %d bytes", len(msg3))

	if err := responder.ProcessMessage3(msg3); err != nil {
		t.Fatalf("ProcessMessage3: %v", err)
	}

	iCtx, err := initiator.ExportOSCORE()
	if err != nil {
		t.Fatalf("Initiator ExportOSCORE: %v", err)
	}
	rCtx, err := responder.ExportOSCORE()
	if err != nil {
		t.Fatalf("Responder ExportOSCORE: %v", err)
	}

	if !bytes.Equal(iCtx.MasterSecret, rCtx.MasterSecret) {
		t.Fatal("Master Secret mismatch")
	}
	if !bytes.Equal(iCtx.MasterSalt, rCtx.MasterSalt) {
		t.Fatal("Master Salt mismatch")
	}

	if !bytes.Equal(iCtx.SenderID, rCtx.RecipientID) {
		t.Fatal("Initiator SenderID should equal Responder RecipientID")
	}
	if !bytes.Equal(iCtx.RecipientID, rCtx.SenderID) {
		t.Fatal("Initiator RecipientID should equal Responder SenderID")
	}

	t.Logf("Master Secret: %x", iCtx.MasterSecret)
	t.Logf("Master Salt: %x", iCtx.MasterSalt)
}

func TestHandshake_WrongPeerKey(t *testing.T) {
	iPub, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	initiator, _ := NewInitiator(InitiatorConfig{
		Suite:        Suite0,
		PrivateKey:   iPriv,
		PeerPublic:   wrongPub,
		ConnectionID: []byte{0x01},
	})

	responder, _ := NewResponder(ResponderConfig{
		Suite:        Suite0,
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x02},
	})

	msg1, _ := initiator.CreateMessage1()
	msg2, err := responder.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1 should succeed: %v", err)
	}

	_, err = initiator.ProcessMessage2(msg2)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestMalformedMessage1(t *testing.T) {
	_, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	iPub, _, _ := ed25519.GenerateKey(rand.Reader)

	responder, _ := NewResponder(ResponderConfig{
		Suite:        Suite0,
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x02},
	})

	_, err := responder.ProcessMessage1([]byte{0xff, 0xff, 0xff})
	if !errors.Is(err, ErrMessageFormat) {
		t.Fatalf("expected ErrMessageFormat, got: %v", err)
	}
}

func TestExportOSCORE_BeforeComplete(t *testing.T) {
	_, iPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, _, _ := ed25519.GenerateKey(rand.Reader)

	initiator, _ := NewInitiator(InitiatorConfig{
		Suite:        Suite0,
		PrivateKey:   iPriv,
		PeerPublic:   rPub,
		ConnectionID: []byte{0x01},
	})

	_, err := initiator.ExportOSCORE()
	if !errors.Is(err, ErrStateViolation) {
		t.Fatalf("expected ErrStateViolation, got: %v", err)
	}

	_, rPriv, _ := ed25519.GenerateKey(rand.Reader)
	iPub, _, _ := ed25519.GenerateKey(rand.Reader)

	responder, _ := NewResponder(ResponderConfig{
		Suite:        Suite0,
		PrivateKey:   rPriv,
		PeerPublic:   iPub,
		ConnectionID: []byte{0x02},
	})

	_, err = responder.ExportOSCORE()
	if !errors.Is(err, ErrStateViolation) {
		t.Fatalf("expected ErrStateViolation, got: %v", err)
	}
}
