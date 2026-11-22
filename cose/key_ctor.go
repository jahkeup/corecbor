// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import "fmt"

// NewSignerFromKey returns a Signer for a private COSE_Key. The key's
// key_ops must permit sign. Its alg, when set, selects the algorithm the
// Signer emits and must be one the key can sign with: the polymorphic or
// fully-specified form of the key's algorithm (RFC 9864), or any RSA
// algorithm for an RSA key; otherwise it is ErrInvalidKey. NewSigner is
// unchanged and does not look at key_ops.
func NewSignerFromKey(k *Key, opts ...SignerOption) (*Signer, error) {
	if !k.Permits(KeyOpSign) {
		return nil, fmt.Errorf("%w: key_ops do not permit sign", ErrInvalidKey)
	}
	priv, err := k.Signer()
	if err != nil {
		return nil, err
	}
	if a, ok := k.Algorithm(); ok {
		implied, err := algForKey(priv)
		if err != nil {
			return nil, err
		}
		if !signerCanEmit(a, implied) {
			return nil, fmt.Errorf("%w: key alg %s, key type implies %s", ErrInvalidKey, a, implied)
		}
		opts = append([]SignerOption{withKeyAlgorithm(a)}, opts...)
	}
	s, err := NewSigner(priv, opts...)
	if err != nil {
		return nil, err
	}
	if a, ok := k.Algorithm(); ok && a != s.alg {
		return nil, fmt.Errorf("%w: key alg %s, signer would emit %s", ErrInvalidKey, a, s.alg)
	}
	return s, nil
}

// withKeyAlgorithm selects the COSE_Key's alg as the Signer's algorithm.
// NewSignerFromKey has already checked that the key can sign with it.
func withKeyAlgorithm(a Algorithm) SignerOption {
	return func(s *Signer) { s.alg = a }
}

// NewVerifierFromKey returns a Verifier for a COSE_Key. The key's
// key_ops must permit verify, and its alg, when set, must match the key
// type (ErrInvalidKey otherwise). For an RSA key, a set alg is the only
// algorithm accepted unless WithAllowedAlgorithms says otherwise.
func NewVerifierFromKey(k *Key, opts ...VerifierOption) (*Verifier, error) {
	if !k.Permits(KeyOpVerify) {
		return nil, fmt.Errorf("%w: key_ops do not permit verify", ErrInvalidKey)
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	v, err := NewVerifier(pub, opts...)
	if err != nil {
		return nil, err
	}
	a, ok := k.Algorithm()
	if !ok {
		return v, nil
	}
	if v.alg != algRSAFamily {
		if !sameSignatureFamily(a, v.alg) {
			return nil, fmt.Errorf("%w: key alg %s, key type implies %s", ErrInvalidKey, a, v.alg)
		}
		// A key restricted to one form (RFC 9052 §7.1 alg) only verifies
		// messages using it.
		if v.policy.allowed == nil {
			v.policy.allowed = []Algorithm{a}
		}
		return v, nil
	}
	switch a {
	case AlgPS256, AlgPS384, AlgPS512, AlgRS256, AlgRS384, AlgRS512:
	default:
		return nil, fmt.Errorf("%w: key alg %s on an RSA key", ErrInvalidKey, a)
	}
	if v.policy.allowed == nil {
		v.policy.allowed = []Algorithm{a}
	}
	return v, nil
}
