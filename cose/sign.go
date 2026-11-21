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
	"slices"

	"github.com/jahkeup/corecbor"
)

type SignerOption func(*Signer)

func WithSignerExternalData(ext []byte) SignerOption {
	return func(s *Signer) { s.external = ext }
}

// Signer signs COSE_Sign1 and COSE_Sign messages. A Signer is safe for
// concurrent use after construction, provided its key is.
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
		enc: sharedEncoder,
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
	digest, err := hashData(hash, data)
	if err != nil {
		return nil, err
	}
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

// WithAllowedAlgorithms restricts which algorithms the Verifier accepts.
// The message's alg header must also match the key: without this option
// the only accepted algorithm is the one the key implies.
func WithAllowedAlgorithms(algs ...Algorithm) VerifierOption {
	return func(v *Verifier) { v.policy.allowed = slices.Clone(algs) }
}

// WithKnownCriticalHeaders declares header labels (int or string) that
// the caller processes itself. A message whose crit header (RFC 9052
// §3.1) lists a label outside this set and the RFC 9052 labels 1-6 is
// rejected with ErrCriticalHeader, because nobody would process it.
func WithKnownCriticalHeaders(labels ...any) VerifierOption {
	return func(v *Verifier) { v.policy.knownCrit = append(v.policy.knownCrit, normalizeLabels(labels)...) }
}

// WithLegacyAlgorithmFromKey restores v0.2.2 behavior: the message's
// alg header is ignored and the signature is checked with the
// algorithm the key implies.
//
// Deprecated: an unbound alg header is a contract defect (RFC 9052
// §3.1, proposal 027 H2). Retained for migration only; removed no
// earlier than v0.32.0.
func WithLegacyAlgorithmFromKey() VerifierOption {
	return func(v *Verifier) { v.policy.legacyAlg = true }
}

// WithLegacyIgnoreCritical restores v0.2.2 behavior: the crit header is
// not processed.
//
// Deprecated: RFC 9052 §3.1 requires critical headers to be understood
// (proposal 027 H3). Retained for migration only; removed no earlier
// than v0.32.0.
func WithLegacyIgnoreCritical() VerifierOption {
	return func(v *Verifier) { v.policy.legacyCrit = true }
}

// Verifier verifies COSE_Sign1 and COSE_Sign messages. A Verifier is
// safe for concurrent use after construction, including concurrent
// verification of the same message.
type Verifier struct {
	key      crypto.PublicKey
	alg      Algorithm
	external []byte
	enc      *corecbor.Encoder
	policy   headerPolicy
}

func NewVerifier(key crypto.PublicKey, opts ...VerifierOption) (*Verifier, error) {
	alg, err := algForPublicKey(key)
	if err != nil {
		return nil, err
	}
	v := &Verifier{
		key: key,
		alg: alg,
		enc: sharedEncoder,
	}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// Verify checks the signature of a Sign1 message. A nil msg.Payload
// means the payload is detached (RFC 9052 §2) and Verify returns
// ErrMissingPayload; use VerifyDetached, or set msg.Payload first. An
// empty, non-nil payload is verified as the empty byte string.
func (v *Verifier) Verify(msg *Sign1) error {
	if msg.Payload == nil {
		return ErrMissingPayload
	}
	return v.verifySign1(msg, msg.Payload)
}

// VerifyDetached checks the signature of a Sign1 message whose payload
// is transported separately. payload is the detached content; nil is
// treated as the empty byte string. msg.Payload is ignored.
func (v *Verifier) VerifyDetached(msg *Sign1, payload []byte) error {
	return v.verifySign1(msg, payload)
}

func (v *Verifier) verifySign1(msg *Sign1, payload []byte) error {
	if err := v.checkLayer(&msg.Protected, &msg.Unprotected); err != nil {
		return err
	}
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return err
	}

	toBeSigned, err := encodeSigStructure(v.enc, protectedBytes, v.external, payload)
	if err != nil {
		return err
	}

	return v.verifyBytes(toBeSigned, msg.Signature)
}

// checkLayer applies the verifier's header policy (alg binding and
// crit) to the layer carrying the signature.
func (v *Verifier) checkLayer(prot, unprot *Headers) error {
	if err := checkCrit(prot, unprot, &v.policy); err != nil {
		return err
	}
	return bindAlg(prot, unprot, v.alg, &v.policy)
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
	digest, err := hashData(hash, data)
	if err != nil {
		return err
	}
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
	return enc.Encode(nil, corecbor.MakeArrayFromSlice(elems[:]))
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

func hashData(h crypto.Hash, data []byte) ([]byte, error) {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		return d[:], nil
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:], nil
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:], nil
	default:
		return nil, fmt.Errorf("%w: unsupported hash %v", ErrUnsupportedAlgorithm, h)
	}
}

// derToRawECDSA converts an ASN.1 DER ECDSA signature to raw R||S format.
func derToRawECDSA(der []byte, curve elliptic.Curve) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("%w: signer returned invalid DER: %w", ErrInvalidKey, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: signer returned trailing bytes after DER signature", ErrInvalidKey)
	}
	size := curveKeySize(curve)
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, fmt.Errorf("%w: signer returned a non-positive ECDSA component", ErrInvalidKey)
	}
	r, s := sig.R.Bytes(), sig.S.Bytes()
	if len(r) > size || len(s) > size {
		return nil, fmt.Errorf("%w: ECDSA component longer than %d bytes", ErrInvalidKey, size)
	}
	out := make([]byte, 2*size)
	copy(out[size-len(r):size], r)
	copy(out[2*size-len(s):], s)
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
