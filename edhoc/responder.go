// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/edhoc/internal/aesccm"
)

type responderState int

const (
	responderStateInit responderState = iota
	responderStateSentMsg2
	responderStateComplete
)

type ResponderConfig struct {
	Suites       []CipherSuite
	PrivateKey   crypto.Signer
	PeerPublic   crypto.PublicKey
	ConnectionID []byte

	Credential     *Credential
	PeerCredential *Credential
	CWTIssuerKey   crypto.PublicKey
}

type Responder struct {
	cfg   ResponderConfig
	suite CipherSuite
	sp    suiteParams
	state responderState

	ephPriv *ecdh.PrivateKey
	ephPub  *ecdh.PublicKey

	connectionID []byte
	peerConnID   []byte

	message1Raw []byte
	th2         []byte
	th3         []byte
	th4         []byte
	prk2e       []byte
	prk3e2m     []byte
	prk4e3m     []byte

	ciphertext2 []byte
}

func NewResponder(cfg ResponderConfig) (*Responder, error) {
	if len(cfg.Suites) == 0 {
		return nil, fmt.Errorf("%w: no suites specified", ErrUnsupportedSuite)
	}
	for _, s := range cfg.Suites {
		if !isSuiteSupported(s) {
			return nil, ErrUnsupportedSuite
		}
	}
	if cfg.PrivateKey == nil || cfg.PeerPublic == nil {
		return nil, fmt.Errorf("%w: missing keys", ErrStateViolation)
	}

	cid := cfg.ConnectionID
	if cid == nil {
		cid = make([]byte, 1)
		if _, err := rand.Read(cid); err != nil {
			return nil, err
		}
		cid[0] = cid[0] % 24
	}

	return &Responder{
		cfg:          cfg,
		state:        responderStateInit,
		connectionID: cid,
	}, nil
}

func (r *Responder) ProcessMessage1(msg1Raw []byte) ([]byte, error) {
	if r.state != responderStateInit {
		return nil, ErrStateViolation
	}

	msg1, err := decodeMessage1(msg1Raw)
	if err != nil {
		return nil, err
	}

	if msg1.Method != 0 {
		return nil, fmt.Errorf("%w: unsupported method %d", ErrUnsupportedSuite, msg1.Method)
	}

	// Suite negotiation: find the first initiator-proposed suite we support
	negotiated, ok := r.negotiateSuite(msg1.Suites)
	if !ok {
		return nil, ErrUnsupportedSuite
	}
	r.suite = negotiated
	r.sp = getSuiteParams(negotiated)

	peerEph, err := r.sp.DHCurve.NewPublicKey(msg1.GX)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid G_X: %v", ErrMessageFormat, err)
	}

	r.peerConnID = msg1.CI
	r.message1Raw = msg1Raw

	ephPriv, err := r.sp.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	r.ephPriv = ephPriv
	r.ephPub = ephPriv.PublicKey()

	sharedSecret, err := computeSharedSecret(r.ephPriv, peerEph)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %v", ErrAuthentication, err)
	}

	r.prk2e = extractPRK2e(sharedSecret)
	r.prk3e2m = r.prk2e
	r.prk4e3m = r.prk2e

	r.th2 = computeTH2(r.message1Raw, r.ephPub.Bytes(), r.connectionID)

	ciphertext2, err := r.encryptMessage2()
	if err != nil {
		return nil, err
	}
	r.ciphertext2 = ciphertext2

	r.th3 = computeTH3(r.th2, ciphertext2)
	r.state = responderStateSentMsg2

	return encodeMessage2(&message2{
		GY:         r.ephPub.Bytes(),
		CR:         r.connectionID,
		Ciphertext: ciphertext2,
	})
}

func (r *Responder) negotiateSuite(proposed []CipherSuite) (CipherSuite, bool) {
	for _, ps := range proposed {
		for _, rs := range r.cfg.Suites {
			if ps == rs {
				return ps, true
			}
		}
	}
	return 0, false
}

func (r *Responder) encryptMessage2() ([]byte, error) {
	var idCredR []byte
	var err error
	if r.cfg.Credential != nil && r.cfg.Credential.Type == CredentialCWT {
		idCredR, err = encodeIDCredCWT(r.cfg.Credential.CWTBytes)
	} else {
		idCredR, err = encodeIDCredFromSigner(r.cfg.PrivateKey)
	}
	if err != nil {
		return nil, err
	}

	mac2, err := edhocKDF(r.prk3e2m, r.th2, "MAC_2", r.sp.AEADTagSize)
	if err != nil {
		return nil, err
	}

	signedData, err := buildSignStruct("Signature1", idCredR, r.th2, mac2)
	if err != nil {
		return nil, err
	}
	signature, err := computeSignature(r.cfg.PrivateKey, signedData)
	if err != nil {
		return nil, err
	}

	var plaintext2 []byte
	plaintext2 = append(plaintext2, idCredR...)
	sigEnc, err := cborEncodeValue(nil, cbor.Bytes(signature))
	if err != nil {
		return nil, err
	}
	plaintext2 = append(plaintext2, sigEnc...)

	k2e, err := edhocKDF(r.prk2e, r.th2, "K_2e", r.sp.AEADKeySize)
	if err != nil {
		return nil, err
	}
	iv2e, err := edhocKDF(r.prk2e, r.th2, "IV_2e", r.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aead, err := aesccm.New(k2e, r.sp.AEADTagSize, r.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aad, err := encodeCBORArray(cbor.Bytes(r.th2))
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, iv2e, plaintext2, aad), nil
}

func (r *Responder) ProcessMessage3(msg3Raw []byte) error {
	if r.state != responderStateSentMsg2 {
		return ErrStateViolation
	}

	msg3, err := decodeMessage3(msg3Raw)
	if err != nil {
		return err
	}

	k3e, err := edhocKDF(r.prk3e2m, r.th3, "K_3e", r.sp.AEADKeySize)
	if err != nil {
		return err
	}
	iv3e, err := edhocKDF(r.prk3e2m, r.th3, "IV_3e", r.sp.AEADNonceLen)
	if err != nil {
		return err
	}

	aead, err := aesccm.New(k3e, r.sp.AEADTagSize, r.sp.AEADNonceLen)
	if err != nil {
		return err
	}

	aad, err := encodeCBORArray(cbor.Bytes(r.th3))
	if err != nil {
		return err
	}

	plaintext3, err := aead.Open(nil, iv3e, msg3.Ciphertext, aad)
	if err != nil {
		return fmt.Errorf("%w: AEAD open failed: %v", ErrAuthentication, err)
	}

	if err := r.verifyInitiatorSignature(plaintext3); err != nil {
		return err
	}

	r.th4 = computeTH4(r.th3, msg3.Ciphertext)
	r.state = responderStateComplete
	return nil
}

// CreateMessage4 creates an optional message_4 for explicit key confirmation.
// Only callable after ProcessMessage3 succeeds (responder is in complete state).
func (r *Responder) CreateMessage4() ([]byte, error) {
	if r.state != responderStateComplete {
		return nil, ErrStateViolation
	}

	k4, err := edhocKDF(r.prk4e3m, r.th4, "K_4", r.sp.AEADKeySize)
	if err != nil {
		return nil, err
	}
	iv4, err := edhocKDF(r.prk4e3m, r.th4, "IV_4", r.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aead, err := aesccm.New(k4, r.sp.AEADTagSize, r.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aad, err := encodeCBORArray(cbor.Bytes(r.th4))
	if err != nil {
		return nil, err
	}

	ciphertext4 := aead.Seal(nil, iv4, []byte{}, aad)

	return cborEncodeValue(nil, cbor.Bytes(ciphertext4))
}

func (r *Responder) verifyInitiatorSignature(plaintext3 []byte) error {
	idCred, rest, err := decodeOneValue(plaintext3)
	if err != nil {
		return fmt.Errorf("%w: decoding ID_CRED_I: %v", ErrMessageFormat, err)
	}

	sig, _, err := decodeOneValue(rest)
	if err != nil {
		return fmt.Errorf("%w: decoding signature: %v", ErrMessageFormat, err)
	}
	ok := sig.Kind() == cbor.KindBytes
	sigBytes := sig.BytesVal()
	if !ok {
		return fmt.Errorf("%w: signature must be bstr", ErrMessageFormat)
	}

	mac3, err := edhocKDF(r.prk4e3m, r.th3, "MAC_3", r.sp.AEADTagSize)
	if err != nil {
		return err
	}

	idCredEnc, err := cborEncodeValue(nil, idCred)
	if err != nil {
		return err
	}
	signedData, err := buildSignStruct("Signature1", idCredEnc, r.th3, mac3)
	if err != nil {
		return err
	}

	peerPub := r.cfg.PeerPublic
	if r.cfg.PeerCredential != nil && r.cfg.PeerCredential.Type == CredentialCWT {
		ok := idCred.Kind() == cbor.KindBytes
		cwtBytes := idCred.BytesVal()
		if !ok {
			return fmt.Errorf("%w: CWT credential ID_CRED must be bstr", ErrMessageFormat)
		}
		issuerKey := r.cfg.CWTIssuerKey
		if issuerKey == nil {
			issuerKey = r.cfg.PeerPublic
		}
		peerPub, err = extractPublicKeyFromCWT([]byte(cwtBytes), issuerKey)
		if err != nil {
			return err
		}
	}

	if err := verifySignature(peerPub, signedData, []byte(sigBytes)); err != nil {
		return ErrAuthentication
	}
	return nil
}
