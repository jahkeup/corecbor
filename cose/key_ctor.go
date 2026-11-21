// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import "fmt"

// NewSignerFromKey returns a Signer for a private COSE_Key. The key's
// key_ops must permit sign, and its alg, when set, must be the algorithm
// the key implies; otherwise it is ErrInvalidKey. NewSigner is unchanged
// and does not look at key_ops.
func NewSignerFromKey(k *Key, opts ...SignerOption) (*Signer, error) {
	if !k.Permits(KeyOpSign) {
		return nil, fmt.Errorf("%w: key_ops do not permit sign", ErrInvalidKey)
	}
	priv, err := k.Signer()
	if err != nil {
		return nil, err
	}
	s, err := NewSigner(priv, opts...)
	if err != nil {
		return nil, err
	}
	if a, ok := k.Algorithm(); ok && a != s.alg {
		return nil, fmt.Errorf("%w: key alg %s, key type implies %s", ErrInvalidKey, a, s.alg)
	}
	return s, nil
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
		if a != v.alg {
			return nil, fmt.Errorf("%w: key alg %s, key type implies %s", ErrInvalidKey, a, v.alg)
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
