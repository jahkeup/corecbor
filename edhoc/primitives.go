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
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

// ephemeralKey creates the ephemeral DH key. With a non-nil Rand the
// private key bytes are read from it directly (so RFC 9529 traces can
// supply X and Y); otherwise crypto/rand is used.
func (s *rfcSuite) ephemeralKey(r io.Reader) (*ecdh.PrivateKey, error) {
	if r == nil {
		return s.curve.GenerateKey(rand.Reader)
	}
	n := 32
	if s.curve == ecdh.P384() {
		n = 48
	}
	for range 16 {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("%w: reading ephemeral key: %w", ErrStateViolation, err)
		}
		k, err := s.curve.NewPrivateKey(b)
		clear(b)
		if err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: Rand produced no valid ephemeral key", ErrStateViolation)
}

// encodePublic returns the on-wire form of an ephemeral or static DH
// public key: the X25519 u-coordinate, or the P-curve x-coordinate
// (RFC 9528 §3.7).
func (s *rfcSuite) encodePublic(pub *ecdh.PublicKey) []byte {
	b := pub.Bytes()
	if s.curve == ecdh.X25519() {
		return b
	}
	size := (len(b) - 1) / 2
	return append([]byte{}, b[1:1+size]...)
}

func (s *rfcSuite) publicLen() int {
	switch s.curve {
	case ecdh.P384():
		return 48
	default:
		return 32
	}
}

// decodePublic parses a peer DH public key from its on-wire form,
// rejecting points that are not on the curve. For P-curves only the
// x-coordinate is sent; either y gives the same ECDH result.
func (s *rfcSuite) decodePublic(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != s.publicLen() {
		return nil, fmt.Errorf("%w: DH public key is %d bytes, want %d", ErrMessageFormat, len(b), s.publicLen())
	}
	if s.curve == ecdh.X25519() {
		pub, err := s.curve.NewPublicKey(b)
		if err != nil {
			return nil, fmt.Errorf("%w: DH public key: %w", ErrMessageFormat, err)
		}
		return pub, nil
	}
	params := s.ellipticCurve().Params()
	x := new(big.Int).SetBytes(b)
	if x.Cmp(params.P) >= 0 {
		return nil, fmt.Errorf("%w: DH public key x-coordinate out of range", ErrMessageFormat)
	}
	// y^2 = x^3 - 3x + b; P-256 and P-384 have p ≡ 3 (mod 4), so
	// y = (y^2)^((p+1)/4).
	y2 := new(big.Int).Exp(x, big.NewInt(3), params.P)
	y2.Sub(y2, new(big.Int).Mul(x, big.NewInt(3)))
	y2.Add(y2, params.B)
	y2.Mod(y2, params.P)
	exp := new(big.Int).Add(params.P, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, params.P)
	if new(big.Int).Exp(y, big.NewInt(2), params.P).Cmp(y2) != 0 {
		return nil, fmt.Errorf("%w: DH public key is not on the curve", ErrMessageFormat)
	}
	size := len(b)
	point := make([]byte, 1+2*size)
	point[0] = 4
	x.FillBytes(point[1 : 1+size])
	y.FillBytes(point[1+size:])
	pub, err := s.curve.NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("%w: DH public key: %w", ErrMessageFormat, err)
	}
	return pub, nil
}

func (s *rfcSuite) ecdh(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	if priv.Curve() != s.curve || pub.Curve() != s.curve {
		return nil, fmt.Errorf("%w: DH key is not on the suite's curve", ErrUnsupportedSuite)
	}
	z, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH: %w", ErrAuthentication, err)
	}
	return z, nil
}

// staticPublic converts a credential's public key to the suite's DH
// key type.
func (s *rfcSuite) staticPublic(pub crypto.PublicKey) (*ecdh.PublicKey, error) {
	switch k := pub.(type) {
	case *ecdh.PublicKey:
		if k.Curve() == s.curve {
			return k, nil
		}
	case *ecdsa.PublicKey:
		e, err := k.ECDH()
		if err == nil && e.Curve() == s.curve {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%w: peer credential has no static DH key for this suite", ErrAuthentication)
}

func (s *rfcSuite) staticPrivate(dh *ecdh.PrivateKey, signer crypto.Signer) (*ecdh.PrivateKey, error) {
	if dh != nil {
		if dh.Curve() != s.curve {
			return nil, fmt.Errorf("%w: DHKey is not on the suite's curve", ErrUnsupportedSuite)
		}
		return dh, nil
	}
	if k, ok := signer.(*ecdsa.PrivateKey); ok {
		e, err := k.ECDH()
		if err == nil && e.Curve() == s.curve {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%w: static DH authentication needs DHKey on the suite's curve", ErrStateViolation)
}

// sign produces a COSE signature (RFC 9053: raw r||s for ECDSA).
func (s *rfcSuite) sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: signature authentication needs PrivateKey", ErrStateViolation)
	}
	switch s.sig {
	case sigEdDSA:
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return nil, fmt.Errorf("%w: suite %d signs with EdDSA", ErrUnsupportedSuite, s.id)
		}
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("%w: signing: %w", ErrAuthentication, err)
		}
		return sig, nil
	default:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		size, h := s.ecdsaParams()
		if !ok || (pub.Curve.Params().BitSize+7)/8 != size {
			return nil, fmt.Errorf("%w: suite %d signs with ECDSA on a %d-byte curve", ErrUnsupportedSuite, s.id, size)
		}
		digest := hashOf(h, msg)
		der, err := signer.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, fmt.Errorf("%w: signing: %w", ErrAuthentication, err)
		}
		return derToRaw(der, size)
	}
}

func (s *rfcSuite) verify(pub crypto.PublicKey, msg, sig []byte) error {
	switch s.sig {
	case sigEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: peer credential is not an Ed25519 key", ErrAuthentication)
		}
		if !ed25519.Verify(k, msg, sig) {
			return fmt.Errorf("%w: signature", ErrAuthentication)
		}
		return nil
	default:
		k, ok := pub.(*ecdsa.PublicKey)
		size, h := s.ecdsaParams()
		if !ok || (k.Curve.Params().BitSize+7)/8 != size {
			return fmt.Errorf("%w: peer credential is not an ECDSA key for this suite", ErrAuthentication)
		}
		if len(sig) != 2*size {
			return fmt.Errorf("%w: signature length", ErrAuthentication)
		}
		r := new(big.Int).SetBytes(sig[:size])
		ss := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, hashOf(h, msg), r, ss) {
			return fmt.Errorf("%w: signature", ErrAuthentication)
		}
		return nil
	}
}

func (s *rfcSuite) ecdsaParams() (int, crypto.Hash) {
	if s.sig == sigES384 {
		return 48, crypto.SHA384
	}
	return 32, crypto.SHA256
}

func hashOf(h crypto.Hash, msg []byte) []byte {
	if h == crypto.SHA384 {
		d := sha512.Sum384(msg)
		return d[:]
	}
	d := sha256.Sum256(msg)
	return d[:]
}

// derToRaw converts an ASN.1 ECDSA signature to the fixed-size r||s
// form COSE uses, rejecting out-of-range values and trailing bytes.
func derToRaw(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil ||
		sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 8*size || sig.S.BitLen() > 8*size {
		if len(der) == 2*size && err != nil {
			// Some signers return raw r||s already.
			return append([]byte{}, der...), nil
		}
		return nil, fmt.Errorf("%w: signer returned a malformed ECDSA signature", ErrAuthentication)
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}
