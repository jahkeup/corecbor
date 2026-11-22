// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"io"
	"maps"
	"math/big"
	"slices"

	"github.com/jahkeup/corecbor"
)

type SignerOption func(*Signer)

func WithSignerExternalData(ext []byte) SignerOption {
	return func(s *Signer) { s.external = ext }
}

// WithProtectedHeaders sets the protected headers every message signed
// by the Signer carries (for example kid, typ, CWT Claims or x5chain).
// The Signer always sets alg itself: an alg in h that doesn't match the
// key makes NewSigner return ErrAlgorithmMismatch. h is copied.
func WithProtectedHeaders(h Headers) SignerOption {
	return func(s *Signer) { s.protected = maps.Clone(h.params) }
}

// WithUnprotectedHeaders sets the unprotected headers every message
// signed by the Signer carries. A label also set in the protected
// headers makes NewSigner return ErrDuplicateLabel (RFC 9052 §3). h is
// copied.
func WithUnprotectedHeaders(h Headers) SignerOption {
	return func(s *Signer) { s.unprotected = maps.Clone(h.params) }
}

// WithFullySpecifiedAlgorithms makes the Signer emit RFC 9864
// fully-specified identifiers: ESP256/ESP384/ESP512 for P-256/384/521
// keys and Ed25519 for Ed25519 keys, instead of the polymorphic
// ES256/ES384/ES512/EdDSA that NewSigner emits by default. This is the
// recommended setting for new deployments; keep the default when peers
// (for example WebAuthn or mDL verifiers) only accept -7/-8. Verifiers
// accept both forms either way.
func WithFullySpecifiedAlgorithms() SignerOption {
	return func(s *Signer) { s.fullySpecified = true }
}

// ContextSigner is a crypto.Signer that can be cancelled, as remote KMS
// and HSM signers often are. When a Signer's key implements it,
// SignContext passes its ctx through; plain crypto.Signer keys are
// still supported.
type ContextSigner interface {
	crypto.Signer
	SignContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Signer signs COSE_Sign1 and COSE_Sign messages. A Signer is safe for
// concurrent use after construction, provided its key is.
type Signer struct {
	key            crypto.Signer
	alg            Algorithm
	external       []byte
	enc            *corecbor.Encoder
	protected      map[any]any // includes alg after NewSigner
	unprotected    map[any]any
	protectedBytes []byte
	fullySpecified bool
}

// NewSigner returns a Signer for key. The algorithm follows from the key
// type. Any crypto.Signer whose Public() is an ed25519.PublicKey, a
// P-256/384/521 *ecdsa.PublicKey, an *rsa.PublicKey of at least 2048
// bits, or (with a Go 1.27+ toolchain) an *mldsa.PublicKey works,
// including KMS- and HSM-backed signers.
//
// ECDSA and Ed25519 keys sign with the polymorphic ES256/ES384/ES512 and
// EdDSA identifiers unless WithFullySpecifiedAlgorithms is set or the
// protected headers name the fully-specified form (RFC 9864; recommended
// for new deployments). RSA keys sign with PS256 unless the protected
// headers name another RSA algorithm (PS384, PS512, or the
// not-recommended RS256/RS384/RS512).
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
	if s.fullySpecified {
		if fs := fullySpecifiedFor(s.alg); fs != 0 {
			s.alg = fs
		}
	}
	prot, chosen, err := protectedWithAlg(s.protected, s.alg)
	if err != nil {
		return nil, err
	}
	s.alg = chosen
	if err := checkBucketOverlap(prot, s.unprotected); err != nil {
		return nil, err
	}
	if _, err := headerParamsToMap(s.unprotected); err != nil {
		return nil, err
	}
	s.protected = prot
	// Pre-encode the protected headers once; they are invariant for this Signer.
	s.protectedBytes, err = encodeHeaderMap(s.protected)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// protectedWithAlg returns a copy of params with alg set, and the
// algorithm to sign with. An alg already in params selects that
// algorithm when it signs with the same key as alg: the fully-specified
// or polymorphic form of the same operation (RFC 9864), or another RSA
// algorithm for an RSA key. Any other alg is ErrAlgorithmMismatch.
func protectedWithAlg(params map[any]any, alg Algorithm) (map[any]any, Algorithm, error) {
	if v, ok := params[headerLabelAlgorithm]; ok {
		a, err := algValue(v)
		if err != nil {
			return nil, 0, err
		}
		if !signerCanEmit(a, alg) {
			return nil, 0, fmt.Errorf("%w: protected header alg %s, key implies %s", ErrAlgorithmMismatch, a, alg)
		}
		alg = a
	}
	out := maps.Clone(params)
	if out == nil {
		out = make(map[any]any, 1)
	}
	out[headerLabelAlgorithm] = int64(alg)
	return out, alg, nil
}

// isRSAAlg reports whether a is an RSA signature algorithm.
func isRSAAlg(a Algorithm) bool {
	switch a {
	case AlgPS256, AlgPS384, AlgPS512, AlgRS256, AlgRS384, AlgRS512:
		return true
	}
	return false
}

// checkBucketOverlap rejects a label set in both buckets (RFC 9052 §3).
func checkBucketOverlap(prot, unprot map[any]any) error {
	for label := range unprot {
		if _, dup := prot[label]; dup {
			return fmt.Errorf("%w: label %v in both buckets", ErrDuplicateLabel, label)
		}
	}
	return nil
}

// Sign signs payload into a new Sign1 carrying the Signer's headers.
func (s *Signer) Sign(payload []byte) (*Sign1, error) {
	return s.SignContext(context.Background(), payload)
}

// SignContext is Sign with a context, passed to the key when it
// implements ContextSigner. A cancelled ctx stops signing with ctx.Err().
func (s *Signer) SignContext(ctx context.Context, payload []byte) (*Sign1, error) {
	msg := &Sign1{
		Protected:   Headers{params: s.protected, raw: s.protectedBytes},
		Unprotected: Headers{params: s.unprotected},
		Payload:     payload,
	}

	toBeSigned, err := encodeSigStructure(s.enc, s.protectedBytes, s.external, payload)
	if err != nil {
		return nil, err
	}

	sig, err := s.signBytes(ctx, s.alg, toBeSigned)
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

// SignDetached signs payload and returns a Sign1 whose Payload is nil:
// the signature covers payload, which travels separately (RFC 9052 §2)
// and is supplied to Verifier.VerifyDetached.
func (s *Signer) SignDetached(payload []byte) (*Sign1, error) {
	if payload == nil {
		payload = []byte{}
	}
	msg, err := s.Sign(payload)
	if err != nil {
		return nil, err
	}
	msg.Payload = nil
	return msg, nil
}

// Sign1 signs msg in place: msg.Protected and msg.Unprotected are merged
// over the Signer's own headers (message values win), alg is set from
// the key, and msg.Signature covers msg.Payload. An alg in msg that
// doesn't match the key is ErrAlgorithmMismatch, and a label in both
// buckets is ErrDuplicateLabel. A nil msg.Payload is signed as the empty
// byte string and stays detached.
func (s *Signer) Sign1(msg *Sign1) error {
	return s.Sign1Context(context.Background(), msg)
}

// Sign1Context is Sign1 with a context (see SignContext).
func (s *Signer) Sign1Context(ctx context.Context, msg *Sign1) error {
	prot := maps.Clone(s.protected)
	delete(prot, headerLabelAlgorithm)
	maps.Copy(prot, msg.Protected.params)
	prot, alg, err := protectedWithAlg(prot, s.alg)
	if err != nil {
		return err
	}
	unprot := maps.Clone(s.unprotected)
	if unprot == nil && len(msg.Unprotected.params) > 0 {
		unprot = make(map[any]any, len(msg.Unprotected.params))
	}
	maps.Copy(unprot, msg.Unprotected.params)
	if err := checkBucketOverlap(prot, unprot); err != nil {
		return err
	}
	if _, err := headerParamsToMap(unprot); err != nil {
		return err
	}
	protBytes, err := encodeHeaderMap(prot)
	if err != nil {
		return err
	}
	toBeSigned, err := encodeSigStructure(s.enc, protBytes, s.external, msg.Payload)
	if err != nil {
		return err
	}
	sig, err := s.signBytes(ctx, alg, toBeSigned)
	if err != nil {
		return err
	}
	msg.Protected = Headers{params: prot, raw: protBytes}
	msg.Unprotected = Headers{params: unprot}
	msg.Signature = sig
	return nil
}

func (s *Signer) signBytes(ctx context.Context, alg Algorithm, data []byte) ([]byte, error) {
	switch alg {
	case AlgPS256, AlgPS384, AlgPS512, AlgRS256, AlgRS384, AlgRS512:
		return s.rsaSign(ctx, alg, data)
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return mldsaSign(s.key, alg, data)
	case AlgEdDSA, AlgEd25519:
		if edKey, ok := s.key.(ed25519.PrivateKey); ok {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// PERF: ed25519.Sign allocates internally (64-byte signature + SHA-512
			// state). This is stdlib crypto — no path to reduce without cgo or asm.
			return ed25519.Sign(edKey, data), nil
		}
		// Any other crypto.Signer with an Ed25519 public key (KMS, HSM):
		// pure Ed25519 signs the message itself, with crypto.Hash(0).
		sig, err := s.keySign(ctx, data, crypto.Hash(0))
		if err != nil {
			return nil, err
		}
		if len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: signer returned %d-byte Ed25519 signature", ErrInvalidKey, len(sig))
		}
		return sig, nil

	case AlgES256, AlgESP256:
		return s.ecdsaSign(ctx, data, crypto.SHA256, elliptic.P256())
	case AlgES384, AlgESP384:
		return s.ecdsaSign(ctx, data, crypto.SHA384, elliptic.P384())
	case AlgES512, AlgESP512:
		return s.ecdsaSign(ctx, data, crypto.SHA512, elliptic.P521())

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// rsaHash returns the hash an RSA signature algorithm uses.
func rsaHash(alg Algorithm) crypto.Hash {
	switch alg {
	case AlgPS256, AlgRS256:
		return crypto.SHA256
	case AlgPS384, AlgRS384:
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// rsaSign signs with RSASSA-PSS (RFC 8230 §2: salt length equals the
// hash length, MGF1 with the same hash) or RSASSA-PKCS1-v1_5 (RFC 8812).
func (s *Signer) rsaSign(ctx context.Context, alg Algorithm, data []byte) ([]byte, error) {
	hash := rsaHash(alg)
	digest, err := hashData(hash, data)
	if err != nil {
		return nil, err
	}
	var opts crypto.SignerOpts = hash
	if alg == AlgPS256 || alg == AlgPS384 || alg == AlgPS512 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
	}
	return s.keySign(ctx, digest, opts)
}

// keySign calls the key, forwarding ctx when it is a ContextSigner.
func (s *Signer) keySign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if cs, ok := s.key.(ContextSigner); ok {
		return cs.SignContext(ctx, rand.Reader, digest, opts)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.key.Sign(rand.Reader, digest, opts)
}

func (s *Signer) ecdsaSign(ctx context.Context, data []byte, hash crypto.Hash, curve elliptic.Curve) ([]byte, error) {
	// PERF: ECDSA path allocates heavily (big.Int for r,s + ASN.1 DER
	// intermediate + raw R||S output). ~83 allocs/op for ES256. Irreducible:
	// stdlib crypto/ecdsa uses big.Int math internally and returns DER which
	// we must decode then re-encode as raw R||S per COSE convention.
	digest, err := hashData(hash, data)
	if err != nil {
		return nil, err
	}
	derSig, err := s.keySign(ctx, digest, hash)
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
	alg, err := v.checkLayer(&msg.Protected, &msg.Unprotected)
	if err != nil {
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

	return v.verifyBytes(alg, toBeSigned, msg.Signature)
}

// rsaDefaultAlgs are the RSA algorithms a Verifier accepts without
// WithAllowedAlgorithms: RSASSA-PSS only (RFC 8230). RSASSA-PKCS1-v1_5
// (RS256…) must be listed explicitly.
var rsaDefaultAlgs = []Algorithm{AlgPS256, AlgPS384, AlgPS512}

// checkLayer applies the verifier's header policy (alg binding and
// crit) to the layer carrying the signature and returns the algorithm
// to verify with. An RSA key implies no single algorithm, so for RSA
// the alg header must be protected and allowed, as for multi-recipient
// bodies.
func (v *Verifier) checkLayer(prot, unprot *Headers) (Algorithm, error) {
	if err := checkCrit(prot, unprot, &v.policy); err != nil {
		return 0, err
	}
	if v.alg == algRSAFamily {
		return multiAlg(prot, unprot, &v.policy, rsaDefaultAlgs)
	}
	// The key implies a signature operation; the header may name it in
	// either its polymorphic or its fully-specified form (RFC 9864), and
	// the header's form is the one bound and allow-listed.
	want := v.alg
	if !v.policy.legacyAlg {
		if a, loc, err := headerAlg(prot, unprot); err == nil && loc != algAbsent && sameSignatureFamily(a, v.alg) {
			want = a
		}
	}
	return want, bindAlg(prot, unprot, want, &v.policy)
}

func (v *Verifier) verifyBytes(alg Algorithm, data, sig []byte) error {
	switch alg {
	case AlgPS256, AlgPS384, AlgPS512, AlgRS256, AlgRS384, AlgRS512:
		return v.rsaVerify(alg, data, sig)
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		return mldsaVerify(v.key, alg, data, sig)
	case AlgEdDSA, AlgEd25519:
		edKey, ok := v.key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected ed25519.PublicKey", ErrInvalidKey)
		}
		if !ed25519.Verify(edKey, data, sig) {
			return ErrVerification
		}
		return nil

	case AlgES256, AlgESP256:
		return v.ecdsaVerify(data, sig, crypto.SHA256, elliptic.P256())
	case AlgES384, AlgESP384:
		return v.ecdsaVerify(data, sig, crypto.SHA384, elliptic.P384())
	case AlgES512, AlgESP512:
		return v.ecdsaVerify(data, sig, crypto.SHA512, elliptic.P521())

	default:
		return ErrUnsupportedAlgorithm
	}
}

// rsaVerify checks an RSASSA-PSS (RFC 8230 §2: salt length equals the
// hash length, MGF1 with the same hash) or RSASSA-PKCS1-v1_5 signature.
func (v *Verifier) rsaVerify(alg Algorithm, data, sig []byte) error {
	pub, ok := v.key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: %s needs an RSA key", ErrAlgorithmMismatch, alg)
	}
	hash := rsaHash(alg)
	digest, err := hashData(hash, data)
	if err != nil {
		return err
	}
	switch alg {
	case AlgPS256, AlgPS384, AlgPS512:
		err = rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
	default:
		err = rsa.VerifyPKCS1v15(pub, hash, digest, sig)
	}
	if err != nil {
		return ErrVerification
	}
	return nil
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

// algRSAFamily marks a Verifier whose RSA key admits several algorithms;
// the message's protected alg selects one (see checkLayer).
const algRSAFamily Algorithm = 0

// minRSABits is the smallest RSA modulus accepted (RFC 8230 §6).
const minRSABits = 2048

func algForKey(key crypto.Signer) (Algorithm, error) {
	alg, err := algForPublicKey(key.Public())
	if err != nil {
		return 0, err
	}
	if alg == algRSAFamily {
		return AlgPS256, nil // RFC 8230; another RSA alg via protected headers
	}
	return alg, nil
}

func algForPublicKey(pub crypto.PublicKey) (Algorithm, error) {
	if a, ok := mldsaAlgForPublic(pub); ok {
		return a, nil
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if p.N == nil || p.N.BitLen() < minRSABits {
			return 0, fmt.Errorf("%w: RSA modulus must be at least %d bits", ErrInvalidKey, minRSABits)
		}
		return algRSAFamily, nil
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
