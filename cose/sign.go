// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

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
	key            crypto.Signer
	alg            Algorithm
	external       []byte
	enc            *corecbor.Encoder
	protectedBytes []byte
}

func NewSigner(key crypto.Signer, opts ...SignerOption) (*Signer, error) {
	alg, err := algForKey(key)
	if err != nil {
		return nil, err
	}
	s := &Signer{
		key: key,
		alg: alg,
		enc: corecbor.New(corecbor.ModeCoreDeterministic),
	}
	for _, o := range opts {
		o(s)
	}
	// Pre-encode the protected headers once; they are invariant for this Signer.
	var h Headers
	h.SetAlgorithm(s.alg)
	s.protectedBytes, err = h.encodeProtected()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Signer) Sign(payload []byte) (*Sign1, error) {
	msg := &Sign1{
		Payload: payload,
	}
	msg.Protected.SetAlgorithm(s.alg)

	toBeSigned, err := encodeSigStructure(s.enc, s.protectedBytes, s.external, payload)
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
		// PERF: ed25519.Sign allocates internally (64-byte signature + SHA-512
		// state). This is stdlib crypto — no path to reduce without cgo or asm.
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
	// PERF: ECDSA path allocates heavily (big.Int for r,s + ASN.1 DER
	// intermediate + raw R||S output). ~83 allocs/op for ES256. Irreducible:
	// stdlib crypto/ecdsa uses big.Int math internally and returns DER which
	// we must decode then re-encode as raw R||S per COSE convention.
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
	enc      *corecbor.Encoder
}

func NewVerifier(key crypto.PublicKey, opts ...VerifierOption) (*Verifier, error) {
	alg, err := algForPublicKey(key)
	if err != nil {
		return nil, err
	}
	v := &Verifier{
		key: key,
		alg: alg,
		enc: corecbor.New(corecbor.ModeCoreDeterministic),
	}
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

	toBeSigned, err := encodeSigStructure(v.enc, protectedBytes, v.external, msg.Payload)
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

// encodeSigStructure encodes Sig_structure = ["Signature1", protectedBytes, externalAAD, payload]
// using a stack-allocated fixed-size array to avoid a heap slice allocation.
func encodeSigStructure(enc *corecbor.Encoder, protectedBytes, external, payload []byte) ([]byte, error) {
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}
	if external == nil {
		external = []byte{}
	}
	if payload == nil {
		payload = []byte{}
	}
	var elems [4]corecbor.Value
	elems[0] = corecbor.Text("Signature1")
	elems[1] = corecbor.Bytes(protectedBytes)
	elems[2] = corecbor.Bytes(external)
	elems[3] = corecbor.Bytes(payload)
	return enc.Encode(nil, corecbor.Array(elems[:]))
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
