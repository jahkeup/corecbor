// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/edhoc/internal/aesccm"
)

type initiatorState int

const (
	initiatorStateInit initiatorState = iota
	initiatorStateSentMsg1
	initiatorStateComplete
)

type InitiatorConfig struct {
	Suites       []CipherSuite
	PrivateKey   crypto.Signer
	PeerPublic   crypto.PublicKey
	ConnectionID []byte

	Credential     *Credential
	PeerCredential *Credential
	CWTIssuerKey   crypto.PublicKey
}

type Initiator struct {
	cfg   InitiatorConfig
	suite CipherSuite
	sp    suiteParams
	state initiatorState

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
}

func NewInitiator(cfg InitiatorConfig) (*Initiator, error) {
	if len(cfg.Suites) == 0 {
		return nil, fmt.Errorf("%w: no suites specified", ErrUnsupportedSuite)
	}
	selectedSuite := cfg.Suites[0]
	if !isSuiteSupported(selectedSuite) {
		return nil, ErrUnsupportedSuite
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

	return &Initiator{
		cfg:          cfg,
		suite:        selectedSuite,
		sp:           getSuiteParams(selectedSuite),
		state:        initiatorStateInit,
		connectionID: cid,
	}, nil
}

func (i *Initiator) CreateMessage1() ([]byte, error) {
	if i.state != initiatorStateInit {
		return nil, ErrStateViolation
	}

	ephPriv, err := i.sp.DHCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	i.ephPriv = ephPriv
	i.ephPub = ephPriv.PublicKey()

	msg := &message1{
		Method:    0,
		Suites:    i.cfg.Suites,
		SuitesSel: i.suite,
		GX:        i.ephPub.Bytes(),
		CI:        i.connectionID,
	}

	raw, err := encodeMessage1(msg)
	if err != nil {
		return nil, err
	}
	i.message1Raw = raw
	i.state = initiatorStateSentMsg1
	return raw, nil
}

func (i *Initiator) ProcessMessage2(msg2Raw []byte) ([]byte, error) {
	if i.state != initiatorStateSentMsg1 {
		return nil, ErrStateViolation
	}

	msg2, err := decodeMessage2(msg2Raw)
	if err != nil {
		return nil, err
	}
	i.peerConnID = msg2.CR

	peerEph, err := i.sp.DHCurve.NewPublicKey(msg2.GY)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid G_Y: %v", ErrMessageFormat, err)
	}

	sharedSecret, err := computeSharedSecret(i.ephPriv, peerEph)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %v", ErrAuthentication, err)
	}

	i.prk2e = extractPRK2e(sharedSecret)
	i.prk3e2m = i.prk2e
	i.prk4e3m = i.prk2e

	i.th2 = computeTH2(i.message1Raw, msg2.GY, msg2.CR)

	plaintext2, err := i.decryptMessage2(msg2.Ciphertext)
	if err != nil {
		return nil, err
	}

	if err := i.verifyResponderSignature(plaintext2); err != nil {
		return nil, err
	}

	i.th3 = computeTH3(i.th2, msg2.Ciphertext)

	msg3Ct, err := i.encryptMessage3()
	if err != nil {
		return nil, err
	}

	i.th4 = computeTH4(i.th3, msg3Ct)
	i.state = initiatorStateComplete

	return encodeMessage3(&message3{Ciphertext: msg3Ct})
}

// ProcessMessage4 verifies optional message_4 key confirmation from the responder.
// Only callable after ProcessMessage2 succeeds (initiator is in complete state).
func (i *Initiator) ProcessMessage4(msg4 []byte) error {
	if i.state != initiatorStateComplete {
		return ErrStateViolation
	}

	ct, _, err := decodeOneValue(msg4)
	if err != nil {
		return fmt.Errorf("%w: decoding message_4: %v", ErrMessageFormat, err)
	}
	ctBytes, ok := ct.(cbor.Bytes)
	if !ok {
		return fmt.Errorf("%w: message_4 must be bstr", ErrMessageFormat)
	}

	k4, err := edhocKDF(i.prk4e3m, i.th4, "K_4", i.sp.AEADKeySize)
	if err != nil {
		return err
	}
	iv4, err := edhocKDF(i.prk4e3m, i.th4, "IV_4", i.sp.AEADNonceLen)
	if err != nil {
		return err
	}

	aead, err := aesccm.New(k4, i.sp.AEADTagSize, i.sp.AEADNonceLen)
	if err != nil {
		return err
	}

	aad, err := encodeCBORArray(cbor.Bytes(i.th4))
	if err != nil {
		return err
	}

	if _, err := aead.Open(nil, iv4, []byte(ctBytes), aad); err != nil {
		return fmt.Errorf("%w: message_4 verification failed: %v", ErrAuthentication, err)
	}

	return nil
}

func (i *Initiator) decryptMessage2(ciphertext []byte) ([]byte, error) {
	k2e, err := edhocKDF(i.prk2e, i.th2, "K_2e", i.sp.AEADKeySize)
	if err != nil {
		return nil, err
	}
	iv2e, err := edhocKDF(i.prk2e, i.th2, "IV_2e", i.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aead, err := aesccm.New(k2e, i.sp.AEADTagSize, i.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aad, err := encodeCBORArray(cbor.Bytes(i.th2))
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, iv2e, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: AEAD open failed: %v", ErrAuthentication, err)
	}
	return plaintext, nil
}

func (i *Initiator) verifyResponderSignature(plaintext2 []byte) error {
	idCred, rest, err := decodeOneValue(plaintext2)
	if err != nil {
		return fmt.Errorf("%w: decoding ID_CRED_R: %v", ErrMessageFormat, err)
	}

	sig, _, err := decodeOneValue(rest)
	if err != nil {
		return fmt.Errorf("%w: decoding signature: %v", ErrMessageFormat, err)
	}
	sigBytes, ok := sig.(cbor.Bytes)
	if !ok {
		return fmt.Errorf("%w: signature must be bstr", ErrMessageFormat)
	}

	mac2, err := edhocKDF(i.prk3e2m, i.th2, "MAC_2", i.sp.AEADTagSize)
	if err != nil {
		return err
	}

	idCredEnc, err := cborEncodeValue(nil, idCred)
	if err != nil {
		return err
	}
	signedData, err := buildSignStruct("Signature1", idCredEnc, i.th2, mac2)
	if err != nil {
		return err
	}

	peerPub := i.cfg.PeerPublic
	if i.cfg.PeerCredential != nil && i.cfg.PeerCredential.Type == CredentialCWT {
		cwtBytes, ok := idCred.(cbor.Bytes)
		if !ok {
			return fmt.Errorf("%w: CWT credential ID_CRED must be bstr", ErrMessageFormat)
		}
		issuerKey := i.cfg.CWTIssuerKey
		if issuerKey == nil {
			issuerKey = i.cfg.PeerPublic
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

func (i *Initiator) encryptMessage3() ([]byte, error) {
	var idCredI []byte
	var err error
	if i.cfg.Credential != nil && i.cfg.Credential.Type == CredentialCWT {
		idCredI, err = encodeIDCredCWT(i.cfg.Credential.CWTBytes)
	} else {
		idCredI, err = encodeIDCredFromSigner(i.cfg.PrivateKey)
	}
	if err != nil {
		return nil, err
	}

	mac3, err := edhocKDF(i.prk4e3m, i.th3, "MAC_3", i.sp.AEADTagSize)
	if err != nil {
		return nil, err
	}

	signedData, err := buildSignStruct("Signature1", idCredI, i.th3, mac3)
	if err != nil {
		return nil, err
	}
	signature, err := computeSignature(i.cfg.PrivateKey, signedData)
	if err != nil {
		return nil, err
	}

	var plaintext3 []byte
	plaintext3 = append(plaintext3, idCredI...)
	sigEnc, err := cborEncodeValue(nil, cbor.Bytes(signature))
	if err != nil {
		return nil, err
	}
	plaintext3 = append(plaintext3, sigEnc...)

	k3e, err := edhocKDF(i.prk3e2m, i.th3, "K_3e", i.sp.AEADKeySize)
	if err != nil {
		return nil, err
	}
	iv3e, err := edhocKDF(i.prk3e2m, i.th3, "IV_3e", i.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aead, err := aesccm.New(k3e, i.sp.AEADTagSize, i.sp.AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aad, err := encodeCBORArray(cbor.Bytes(i.th3))
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, iv3e, plaintext3, aad), nil
}

func buildSignStruct(context string, idCred, th, mac []byte) ([]byte, error) {
	return encodeCBORArray(
		cbor.Text(context),
		cbor.Bytes(idCred),
		cbor.Bytes(th),
		cbor.Bytes(mac),
	)
}

func encodeIDCred(pub []byte) ([]byte, error) {
	return cborEncodeValue(nil, cbor.Map{
		{Key: cbor.Uint(4), Value: cbor.Bytes(pub)},
	})
}

func encodeIDCredFromSigner(signer crypto.Signer) ([]byte, error) {
	pubBytes := marshalPublicKeyRaw(signer.Public())
	return encodeIDCred(pubBytes)
}

func marshalPublicKeyRaw(pub crypto.PublicKey) []byte {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return []byte(k)
	case *ecdsa.PublicKey:
		raw, err := k.Bytes()
		if err != nil {
			return nil
		}
		// Convert uncompressed (0x04||X||Y) to compressed form
		size := (k.Curve.Params().BitSize + 7) / 8
		compressed := make([]byte, 1+size)
		if raw[len(raw)-1]&1 == 0 {
			compressed[0] = 0x02
		} else {
			compressed[0] = 0x03
		}
		copy(compressed[1:], raw[1:1+size])
		return compressed
	default:
		return nil
	}
}

func computeSignature(signer crypto.Signer, data []byte) ([]byte, error) {
	switch k := signer.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, data), nil
	case *ecdsa.PrivateKey:
		hash := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, k, hash[:])
		if err != nil {
			return nil, err
		}
		// Raw R||S format, each component zero-padded to 32 bytes for P-256
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		sig := make([]byte, 2*byteLen)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(sig[byteLen-len(rBytes):byteLen], rBytes)
		copy(sig[2*byteLen-len(sBytes):], sBytes)
		return sig, nil
	default:
		return nil, fmt.Errorf("%w: unsupported signer type", ErrUnsupportedSuite)
	}
}

func verifySignature(pub crypto.PublicKey, data, sig []byte) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, sig) {
			return ErrAuthentication
		}
		return nil
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(data)
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*byteLen {
			return ErrAuthentication
		}
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		if !ecdsa.Verify(k, hash[:], r, s) {
			return ErrAuthentication
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported public key type", ErrUnsupportedSuite)
	}
}
