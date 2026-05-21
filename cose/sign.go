package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/jahkeup/corecbor"
)

type SignerOption func(*Signer)

func WithSignerExternalData(ext []byte) SignerOption {
	return func(s *Signer) { s.external = ext }
}

type Signer struct {
	key      crypto.Signer
	alg      Algorithm
	external []byte
}

func NewSigner(key crypto.Signer, opts ...SignerOption) (*Signer, error) {
	alg, err := algForKey(key)
	if err != nil {
		return nil, err
	}
	s := &Signer{key: key, alg: alg}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func (s *Signer) Sign(payload []byte) (*Sign1, error) {
	msg := &Sign1{
		Payload: payload,
	}
	msg.Protected.SetAlgorithm(s.alg)

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	sigStructure := buildSigStructure(protectedBytes, s.external, payload)
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	toBeSigned, err := enc.Encode(nil, sigStructure)
	if err != nil {
		return nil, err
	}

	sig, err := s.signBytes(toBeSigned)
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (s *Signer) signBytes(data []byte) ([]byte, error) {
	switch s.alg {
	case AlgEdDSA:
		edKey, ok := s.key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected ed25519.PrivateKey", ErrInvalidKey)
		}
		return ed25519.Sign(edKey, data), nil

	case AlgES256:
		return s.ecdsaSign(data, crypto.SHA256, elliptic.P256())
	case AlgES384:
		return s.ecdsaSign(data, crypto.SHA384, elliptic.P384())
	case AlgES512:
		return s.ecdsaSign(data, crypto.SHA512, elliptic.P521())

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func (s *Signer) ecdsaSign(data []byte, hash crypto.Hash, curve elliptic.Curve) ([]byte, error) {
	digest := hashData(hash, data)
	derSig, err := s.key.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, err
	}
	return derToRawECDSA(derSig, curve)
}

type VerifierOption func(*Verifier)

func WithVerifierExternalData(ext []byte) VerifierOption {
	return func(v *Verifier) { v.external = ext }
}

type Verifier struct {
	key      crypto.PublicKey
	alg      Algorithm
	external []byte
}

func NewVerifier(key crypto.PublicKey, opts ...VerifierOption) (*Verifier, error) {
	alg, err := algForPublicKey(key)
	if err != nil {
		return nil, err
	}
	v := &Verifier{key: key, alg: alg}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// Verify checks the signature of a Sign1 message.
// For detached payloads, set msg.Payload before calling Verify.
func (v *Verifier) Verify(msg *Sign1) error {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return err
	}

	sigStructure := buildSigStructure(protectedBytes, v.external, msg.Payload)
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	toBeSigned, err := enc.Encode(nil, sigStructure)
	if err != nil {
		return err
	}

	return v.verifyBytes(toBeSigned, msg.Signature)
}

func (v *Verifier) verifyBytes(data, sig []byte) error {
	switch v.alg {
	case AlgEdDSA:
		edKey, ok := v.key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected ed25519.PublicKey", ErrInvalidKey)
		}
		if !ed25519.Verify(edKey, data, sig) {
			return ErrVerification
		}
		return nil

	case AlgES256:
		return v.ecdsaVerify(data, sig, crypto.SHA256, elliptic.P256())
	case AlgES384:
		return v.ecdsaVerify(data, sig, crypto.SHA384, elliptic.P384())
	case AlgES512:
		return v.ecdsaVerify(data, sig, crypto.SHA512, elliptic.P521())

	default:
		return ErrUnsupportedAlgorithm
	}
}

func (v *Verifier) ecdsaVerify(data, sig []byte, hash crypto.Hash, curve elliptic.Curve) error {
	ecKey, ok := v.key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: expected *ecdsa.PublicKey", ErrInvalidKey)
	}
	digest := hashData(hash, data)
	derSig, err := rawToDerECDSA(sig, curve)
	if err != nil {
		return ErrVerification
	}
	if !ecdsa.VerifyASN1(ecKey, digest, derSig) {
		return ErrVerification
	}
	return nil
}

// Sig_structure = ["Signature1", protectedBytes, externalAAD, payload]
func buildSigStructure(protectedBytes, external, payload []byte) corecbor.Array {
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}
	if external == nil {
		external = []byte{}
	}
	if payload == nil {
		payload = []byte{}
	}
	return corecbor.Array{
		corecbor.Text("Signature1"),
		corecbor.Bytes(protectedBytes),
		corecbor.Bytes(external),
		corecbor.Bytes(payload),
	}
}

func algForKey(key crypto.Signer) (Algorithm, error) {
	return algForPublicKey(key.Public())
}

func algForPublicKey(pub crypto.PublicKey) (Algorithm, error) {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return AlgEdDSA, nil
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			return AlgES256, nil
		case elliptic.P384():
			return AlgES384, nil
		case elliptic.P521():
			return AlgES512, nil
		default:
			return 0, fmt.Errorf("%w: unsupported EC curve", ErrInvalidKey)
		}
	default:
		return 0, fmt.Errorf("%w: unsupported key type %T", ErrInvalidKey, pub)
	}
}

func hashData(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:]
	default:
		panic("unsupported hash")
	}
}

// derToRawECDSA converts an ASN.1 DER ECDSA signature to raw R||S format.
func derToRawECDSA(der []byte, curve elliptic.Curve) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	size := curveKeySize(curve)
	out := make([]byte, 2*size)
	copy(out[size-len(sig.R.Bytes()):size], sig.R.Bytes())
	copy(out[2*size-len(sig.S.Bytes()):], sig.S.Bytes())
	return out, nil
}

// rawToDerECDSA converts a raw R||S ECDSA signature to ASN.1 DER.
func rawToDerECDSA(raw []byte, curve elliptic.Curve) ([]byte, error) {
	size := curveKeySize(curve)
	if len(raw) != 2*size {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(raw), 2*size)
	}
	r := new(big.Int).SetBytes(raw[:size])
	s := new(big.Int).SetBytes(raw[size:])
	var sig struct {
		R, S *big.Int
	}
	sig.R = r
	sig.S = s
	return asn1.Marshal(sig)
}
