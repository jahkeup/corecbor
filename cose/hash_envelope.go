// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"maps"
)

// COSE Hash Envelope header labels (RFC 9995 §3).
const (
	// HeaderPayloadHashAlg (258) is the hash algorithm that produced the
	// payload. It MUST be in the protected bucket.
	HeaderPayloadHashAlg int64 = 258
	// HeaderPreimageContentType (259) is the content format of the bytes
	// that were hashed (a CoAP content-format number or a media type).
	// Protected bucket only.
	HeaderPreimageContentType int64 = 259
	// HeaderPayloadLocation (260) is a hint for retrieving the preimage.
	// Protected bucket only.
	HeaderPayloadLocation int64 = 260
)

// HashEnvelope describes a COSE Hash Envelope (RFC 9995): a COSE_Sign1
// whose payload is the digest of a preimage rather than the preimage
// itself.
type HashEnvelope struct {
	// HashAlg is the RFC 9054 hash algorithm of the payload: AlgSHA256,
	// AlgSHA384, AlgSHA512 or AlgSHA512_256. The "Filter Only"
	// algorithms (SHA-1, SHA-256/64) are not accepted.
	HashAlg Algorithm
	// PreimageContentType, if set, is the content format of the
	// preimage: a uint64 (or non-negative int) CoAP content-format
	// number, or a media-type string.
	PreimageContentType any
	// Location, if non-empty, identifies where the preimage can be
	// retrieved.
	Location string
}

// hashEnvelopeDigest hashes preimage with one of the algorithms a Hash
// Envelope may use.
func hashEnvelopeDigest(alg Algorithm, preimage []byte) ([]byte, error) {
	switch alg {
	case AlgSHA256:
		d := sha256.Sum256(preimage)
		return d[:], nil
	case AlgSHA384:
		d := sha512.Sum384(preimage)
		return d[:], nil
	case AlgSHA512:
		d := sha512.Sum512(preimage)
		return d[:], nil
	case AlgSHA512_256:
		d := sha512.Sum512_256(preimage)
		return d[:], nil
	default:
		return nil, fmt.Errorf("%w: hash envelope hash algorithm %v", ErrUnsupportedAlgorithm, alg)
	}
}

func hashEnvelopeSize(alg Algorithm) (int, error) {
	switch alg {
	case AlgSHA256, AlgSHA512_256:
		return 32, nil
	case AlgSHA384:
		return 48, nil
	case AlgSHA512:
		return 64, nil
	default:
		return 0, fmt.Errorf("%w: hash envelope hash algorithm %v", ErrUnsupportedAlgorithm, alg)
	}
}

// Hash returns the digest of preimage under env.HashAlg.
func (env HashEnvelope) Hash(preimage []byte) ([]byte, error) {
	return hashEnvelopeDigest(env.HashAlg, preimage)
}

// SetHeaders writes env's parameters (258, and 259/260 when set) into h,
// which must be a protected bucket (RFC 9995 §4). It checks the hash
// algorithm and the content type's form; h is left unchanged on error.
func (env HashEnvelope) SetHeaders(h *Headers) error {
	if _, err := hashEnvelopeSize(env.HashAlg); err != nil {
		return err
	}
	out := Headers{params: maps.Clone(h.params)}
	if err := out.SetChecked(HeaderPayloadHashAlg, int64(env.HashAlg)); err != nil {
		return err
	}
	if env.PreimageContentType != nil {
		if err := out.setUintOrText(HeaderPreimageContentType, env.PreimageContentType); err != nil {
			return fmt.Errorf("hash envelope preimage content type: %w", err)
		}
	}
	if env.Location != "" {
		if err := out.SetChecked(HeaderPayloadLocation, env.Location); err != nil {
			return err
		}
	}
	*h = out
	return nil
}

// HashEnvelopeFrom checks msg against the RFC 9995 header rules and
// returns its envelope parameters. It returns an error wrapping
// ErrMalformed when label 258 is missing from (or not an integer in)
// the protected bucket, when 258, 259 or 260 appear in the unprotected
// bucket, when content type (label 3) appears in either bucket, or when
// 259/260 have the wrong type; and ErrUnsupportedAlgorithm for a hash
// algorithm this package doesn't implement.
func HashEnvelopeFrom(msg *Sign1) (HashEnvelope, error) {
	prot, unprot := &msg.Protected, &msg.Unprotected
	for _, label := range []int64{HeaderPayloadHashAlg, HeaderPreimageContentType, HeaderPayloadLocation} {
		if _, ok := unprot.params[label]; ok {
			return HashEnvelope{}, fmt.Errorf("%w: hash envelope label %d in the unprotected bucket", ErrMalformed, label)
		}
	}
	if _, ok := prot.params[headerLabelContentType]; ok {
		return HashEnvelope{}, fmt.Errorf("%w: content type (label 3) in a hash envelope", ErrMalformed)
	}
	if _, ok := unprot.params[headerLabelContentType]; ok {
		return HashEnvelope{}, fmt.Errorf("%w: content type (label 3) in a hash envelope", ErrMalformed)
	}
	raw, ok := prot.params[HeaderPayloadHashAlg]
	if !ok {
		return HashEnvelope{}, fmt.Errorf("%w: hash envelope without payload_hash_alg (label 258)", ErrMalformed)
	}
	alg, ok := raw.(int64)
	if !ok {
		return HashEnvelope{}, fmt.Errorf("%w: payload_hash_alg (label 258) is %T, want int", ErrMalformed, raw)
	}
	env := HashEnvelope{HashAlg: Algorithm(alg)}
	if _, err := hashEnvelopeSize(env.HashAlg); err != nil {
		return HashEnvelope{}, err
	}
	if _, present := prot.params[HeaderPreimageContentType]; present {
		format, mediaType, ok := prot.uintOrText(HeaderPreimageContentType)
		if !ok {
			return HashEnvelope{}, fmt.Errorf("%w: preimage content type (label 259) is not uint or tstr", ErrMalformed)
		}
		if mediaType != "" {
			env.PreimageContentType = mediaType
		} else {
			env.PreimageContentType = format
		}
	}
	if raw, present := prot.params[HeaderPayloadLocation]; present {
		loc, ok := raw.(string)
		if !ok {
			return HashEnvelope{}, fmt.Errorf("%w: payload location (label 260) is %T, want tstr", ErrMalformed, raw)
		}
		env.Location = loc
	}
	return env, nil
}

// SignHashEnvelope hashes preimage with env.HashAlg and signs the
// digest as a COSE Hash Envelope (RFC 9995). env's parameters go in the
// protected bucket, merged with the Signer's own headers. With detached
// the returned message's Payload is nil and the digest travels
// separately (Verifier.VerifyHashEnvelope takes it back).
//
// The Signer's headers must not carry content type (label 3), and must
// not carry labels 258, 259 or 260 in the unprotected bucket.
func (s *Signer) SignHashEnvelope(preimage []byte, env HashEnvelope, detached bool) (*Sign1, error) {
	digest, err := env.Hash(preimage)
	if err != nil {
		return nil, err
	}
	return s.SignHashEnvelopeDigest(digest, env, detached)
}

// SignHashEnvelopeDigest is SignHashEnvelope for a digest the caller has
// already computed (for example streamed, or computed beside a KMS that
// never sees the preimage). The digest length must match env.HashAlg.
func (s *Signer) SignHashEnvelopeDigest(digest []byte, env HashEnvelope, detached bool) (*Sign1, error) {
	return s.signHashEnvelope(context.Background(), &Sign1{}, digest, env, detached)
}

// SignHashEnvelopeMessage signs msg in place as a Hash Envelope over
// digest: env's parameters are added to msg.Protected (which may carry
// other parameters such as kid or CWT Claims), msg.Payload is set to
// digest (or left nil when detached), and the result is checked against
// the RFC 9995 rules before it is returned.
func (s *Signer) SignHashEnvelopeMessage(ctx context.Context, msg *Sign1, digest []byte, env HashEnvelope, detached bool) error {
	signed, err := s.signHashEnvelope(ctx, msg, digest, env, detached)
	if err != nil {
		return err
	}
	*msg = *signed
	return nil
}

func (s *Signer) signHashEnvelope(ctx context.Context, base *Sign1, digest []byte, env HashEnvelope, detached bool) (*Sign1, error) {
	n, err := hashEnvelopeSize(env.HashAlg)
	if err != nil {
		return nil, err
	}
	if len(digest) != n {
		return nil, fmt.Errorf("%w: digest is %d bytes, %v produces %d", ErrMalformed, len(digest), env.HashAlg, n)
	}
	msg := &Sign1{
		Protected:   Headers{params: maps.Clone(base.Protected.params)},
		Unprotected: Headers{params: maps.Clone(base.Unprotected.params)},
	}
	if err := env.SetHeaders(&msg.Protected); err != nil {
		return nil, err
	}
	msg.Payload = digest
	if err := s.Sign1Context(ctx, msg); err != nil {
		return nil, err
	}
	// Sign1 merged the Signer's own headers; check the result as a
	// verifier would, so a Signer configured with content type or an
	// unprotected 258..260 can't produce a non-conforming envelope.
	if _, err := HashEnvelopeFrom(msg); err != nil {
		return nil, err
	}
	if detached {
		msg.Payload = nil
	}
	return msg, nil
}

// VerifyHashEnvelope verifies a COSE Hash Envelope (RFC 9995): it
// applies the header rules (HashEnvelopeFrom), verifies the signature
// over the digest, and, when preimage is non-nil, checks that the
// digest is env.HashAlg(preimage).
//
// The digest is msg.Payload when attached. For a detached payload, pass
// it as digest, or pass nil and supply preimage to have it computed.
// When both msg.Payload and digest are set they must be equal. A digest
// whose length doesn't match the hash algorithm is ErrMalformed; a
// digest or preimage mismatch is ErrVerification.
func (v *Verifier) VerifyHashEnvelope(msg *Sign1, digest, preimage []byte) (HashEnvelope, error) {
	env, d, err := hashEnvelopeInputs(msg, digest, preimage)
	if err != nil {
		return HashEnvelope{}, err
	}
	if err := v.VerifyDetached(msg, d); err != nil {
		return HashEnvelope{}, err
	}
	return env, nil
}

// VerifySign1HashEnvelope is VerifyHashEnvelope with keys from a
// KeyResolver (see VerifySign1).
func VerifySign1HashEnvelope(ctx context.Context, msg *Sign1, digest, preimage []byte, r KeyResolver, opts ...VerifierOption) (HashEnvelope, error) {
	env, d, err := hashEnvelopeInputs(msg, digest, preimage)
	if err != nil {
		return HashEnvelope{}, err
	}
	if err := VerifySign1Detached(ctx, msg, d, r, opts...); err != nil {
		return HashEnvelope{}, err
	}
	return env, nil
}

// hashEnvelopeInputs checks msg's envelope headers and settles the
// digest to verify against: the attached payload, the caller's digest,
// or the hash of the preimage, which must all agree.
func hashEnvelopeInputs(msg *Sign1, digest, preimage []byte) (HashEnvelope, []byte, error) {
	env, err := HashEnvelopeFrom(msg)
	if err != nil {
		return HashEnvelope{}, nil, err
	}
	n, _ := hashEnvelopeSize(env.HashAlg)
	var computed []byte
	if preimage != nil {
		computed, err = env.Hash(preimage)
		if err != nil {
			return HashEnvelope{}, nil, err
		}
	}
	d := msg.Payload
	if d == nil {
		d = digest
	} else if digest != nil && subtle.ConstantTimeCompare(d, digest) != 1 {
		return HashEnvelope{}, nil, fmt.Errorf("%w: supplied digest differs from the attached payload", ErrVerification)
	}
	if d == nil {
		if computed == nil {
			return HashEnvelope{}, nil, ErrMissingPayload
		}
		d = computed
	}
	if len(d) != n {
		return HashEnvelope{}, nil, fmt.Errorf("%w: digest is %d bytes, %v produces %d", ErrMalformed, len(d), env.HashAlg, n)
	}
	if computed != nil && subtle.ConstantTimeCompare(d, computed) != 1 {
		return HashEnvelope{}, nil, fmt.Errorf("%w: digest does not match the preimage", ErrVerification)
	}
	return env, d, nil
}
