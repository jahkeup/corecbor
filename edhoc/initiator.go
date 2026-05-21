package edhoc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

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
	Suite        CipherSuite
	PrivateKey   ed25519.PrivateKey
	PeerPublic   ed25519.PublicKey
	ConnectionID []byte
}

type Initiator struct {
	cfg   InitiatorConfig
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
	if cfg.Suite != Suite0 {
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
		state:        initiatorStateInit,
		connectionID: cid,
	}, nil
}

func (i *Initiator) CreateMessage1() ([]byte, error) {
	if i.state != initiatorStateInit {
		return nil, ErrStateViolation
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	i.ephPriv = ephPriv
	i.ephPub = ephPriv.PublicKey()

	msg := &message1{
		Method: 0,
		Suites: int64(i.cfg.Suite),
		GX:     i.ephPub.Bytes(),
		CI:     i.connectionID,
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

	peerEph, err := ecdh.X25519().NewPublicKey(msg2.GY)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid G_Y: %v", ErrMessageFormat, err)
	}

	sharedSecret, err := computeSharedSecret(i.ephPriv, peerEph)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %v", ErrAuthentication, err)
	}

	i.prk2e = extractPRK2e(sharedSecret)
	i.prk3e2m = i.prk2e // method 0: no static DH
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

func (i *Initiator) decryptMessage2(ciphertext []byte) ([]byte, error) {
	k2e, err := edhocKDF(i.prk2e, i.th2, "K_2e", suite0AEADKeySize)
	if err != nil {
		return nil, err
	}
	iv2e, err := edhocKDF(i.prk2e, i.th2, "IV_2e", suite0AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aead, err := aesccm.New(k2e, suite0AEADTagSize, suite0AEADNonceLen)
	if err != nil {
		return nil, err
	}

	// AAD for message 2: CBOR encoding of [TH_2]
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
	// plaintext2 = ID_CRED_R || Signature_or_MAC_2
	// For RPK with method 0: ID_CRED_R is a CBOR map, signature is Ed25519 sig
	// Simplified: we expect the plaintext to be CBOR sequence: credential_identifier, signature
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

	// MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2", mac_length)
	mac2, err := edhocKDF(i.prk3e2m, i.th2, "MAC_2", suite0AEADTagSize)
	if err != nil {
		return err
	}

	// Construct signed data: ["Signature1", ID_CRED_R, TH_2, MAC_2]
	idCredEnc, err := cborEncodeValue(nil, idCred)
	if err != nil {
		return err
	}
	signedData, err := buildSignStruct("Signature1", idCredEnc, i.th2, mac2)
	if err != nil {
		return err
	}

	if !ed25519.Verify(i.cfg.PeerPublic, signedData, []byte(sigBytes)) {
		return ErrAuthentication
	}
	return nil
}

func (i *Initiator) encryptMessage3() ([]byte, error) {
	// ID_CRED_I: simplified as map {4: kid} where kid = public key bytes
	idCredI, err := encodeIDCred(i.cfg.PrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}

	// MAC_3 = EDHOC-KDF(PRK_4e3m, TH_3, "MAC_3", mac_length)
	mac3, err := edhocKDF(i.prk4e3m, i.th3, "MAC_3", suite0AEADTagSize)
	if err != nil {
		return nil, err
	}

	// Sign: Signature_or_MAC_3
	signedData, err := buildSignStruct("Signature1", idCredI, i.th3, mac3)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(i.cfg.PrivateKey, signedData)

	// Plaintext_3 = ID_CRED_I || Signature_or_MAC_3
	var plaintext3 []byte
	plaintext3 = append(plaintext3, idCredI...)
	sigEnc, err := cborEncodeValue(nil, cbor.Bytes(signature))
	if err != nil {
		return nil, err
	}
	plaintext3 = append(plaintext3, sigEnc...)

	// Encrypt
	k3e, err := edhocKDF(i.prk3e2m, i.th3, "K_3e", suite0AEADKeySize)
	if err != nil {
		return nil, err
	}
	iv3e, err := edhocKDF(i.prk3e2m, i.th3, "IV_3e", suite0AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aead, err := aesccm.New(k3e, suite0AEADTagSize, suite0AEADNonceLen)
	if err != nil {
		return nil, err
	}

	aad, err := encodeCBORArray(cbor.Bytes(i.th3))
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, iv3e, plaintext3, aad), nil
}

// buildSignStruct creates the Sig_structure for signing per COSE:
// Sig_structure = ["Signature1", external_aad, payload]
// In EDHOC context: ["Signature1", << ID_CRED >>, TH, MAC]
func buildSignStruct(context string, idCred, th, mac []byte) ([]byte, error) {
	return encodeCBORArray(
		cbor.Text(context),
		cbor.Bytes(idCred),
		cbor.Bytes(th),
		cbor.Bytes(mac),
	)
}

// encodeIDCred encodes the credential identifier as CBOR map {4: h'<pubkey>'}
// (kid = key identifier, label 4 per COSE Header Parameters)
func encodeIDCred(pub ed25519.PublicKey) ([]byte, error) {
	return cborEncodeValue(nil, cbor.Map{
		{Key: cbor.Uint(4), Value: cbor.Bytes(pub)},
	})
}
