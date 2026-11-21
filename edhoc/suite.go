// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/edhoc/internal/aesccm"
)

// Cipher suites registered by RFC 9528 §10.2 beyond Suite0 and Suite2.
// Suite 25 (X448, SHAKE256) is not supported.
const (
	Suite1  CipherSuite = 1
	Suite3  CipherSuite = 3
	Suite4  CipherSuite = 4
	Suite5  CipherSuite = 5
	Suite6  CipherSuite = 6
	Suite24 CipherSuite = 24
)

type aeadKind int

const (
	aeadCCM8   aeadKind = iota // AES-CCM-16-64-128
	aeadCCM16                  // AES-CCM-16-128-128
	aeadGCM128                 // A128GCM
	aeadGCM256                 // A256GCM
	aeadChaCha                 // ChaCha20/Poly1305
)

type sigKind int

const (
	sigEdDSA sigKind = iota
	sigES256
	sigES384
)

// COSE algorithm identifiers used for the OSCORE context.
const (
	coseAESCCM1664128 cose.Algorithm = 10
	coseA128GCM       cose.Algorithm = 1
	coseA256GCM       cose.Algorithm = 3
	coseChaCha20      cose.Algorithm = 24
	coseHKDFSHA256    cose.Algorithm = -10
)

// rfcSuite is one RFC 9528 §10.2 cipher suite.
type rfcSuite struct {
	id       CipherSuite
	aead     aeadKind
	hash     crypto.Hash
	macLen   int // EDHOC MAC length for static DH authentication
	curve    ecdh.Curve
	sig      sigKind
	appAEAD  aeadKind
	appHash  crypto.Hash
	keyLen   int // EDHOC AEAD key length
	ivLen    int // EDHOC AEAD nonce length
	appKey   int // application AEAD key length
	hashSize int
}

func lookupSuite(id CipherSuite) (*rfcSuite, bool) {
	s, ok := rfcSuites[id]
	return s, ok
}

var rfcSuites = map[CipherSuite]*rfcSuite{
	Suite0:  newSuite(Suite0, aeadCCM8, crypto.SHA256, 8, ecdh.X25519(), sigEdDSA, aeadCCM8, crypto.SHA256),
	Suite1:  newSuite(Suite1, aeadCCM16, crypto.SHA256, 16, ecdh.X25519(), sigEdDSA, aeadCCM8, crypto.SHA256),
	Suite2:  newSuite(Suite2, aeadCCM8, crypto.SHA256, 8, ecdh.P256(), sigES256, aeadCCM8, crypto.SHA256),
	Suite3:  newSuite(Suite3, aeadCCM16, crypto.SHA256, 16, ecdh.P256(), sigES256, aeadCCM8, crypto.SHA256),
	Suite4:  newSuite(Suite4, aeadChaCha, crypto.SHA256, 16, ecdh.X25519(), sigEdDSA, aeadChaCha, crypto.SHA256),
	Suite5:  newSuite(Suite5, aeadChaCha, crypto.SHA256, 16, ecdh.P256(), sigES256, aeadChaCha, crypto.SHA256),
	Suite6:  newSuite(Suite6, aeadGCM128, crypto.SHA256, 16, ecdh.X25519(), sigES256, aeadGCM128, crypto.SHA256),
	Suite24: newSuite(Suite24, aeadGCM256, crypto.SHA384, 16, ecdh.P384(), sigES384, aeadGCM256, crypto.SHA384),
}

func newSuite(id CipherSuite, aead aeadKind, h crypto.Hash, macLen int, curve ecdh.Curve, sig sigKind, appAEAD aeadKind, appHash crypto.Hash) *rfcSuite {
	s := &rfcSuite{id: id, aead: aead, hash: h, macLen: macLen, curve: curve, sig: sig, appAEAD: appAEAD, appHash: appHash, hashSize: h.Size()}
	s.keyLen, s.ivLen = aeadSizes(aead)
	s.appKey, _ = aeadSizes(appAEAD)
	return s
}

func aeadSizes(k aeadKind) (keyLen, nonceLen int) {
	switch k {
	case aeadCCM8, aeadCCM16:
		return 16, 13
	case aeadGCM128:
		return 16, 12
	case aeadGCM256, aeadChaCha:
		return 32, 12
	}
	return 0, 0
}

func (s *rfcSuite) newHash() func() hash.Hash {
	if s.hash == crypto.SHA384 {
		return sha512.New384
	}
	return sha256.New
}

// h is the EDHOC hash over a CBOR sequence.
func (s *rfcSuite) h(parts ...[]byte) []byte {
	hh := s.newHash()()
	for _, p := range parts {
		hh.Write(p)
	}
	return hh.Sum(nil)
}

// extract is EDHOC_Extract: HMAC with salt over ikm (RFC 9528 §4.1.1).
func (s *rfcSuite) extract(salt, ikm []byte) []byte {
	m := hmac.New(s.newHash(), salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// kdf is EDHOC_KDF(PRK, info_label, context, length) (RFC 9528 §4.1.2):
// HKDF-Expand with info = (info_label: int, context: bstr, length: uint).
func (s *rfcSuite) kdf(prk []byte, label int64, context []byte, length int) ([]byte, error) {
	info := encSeq(intItem(label), bstrItem(context), uintItem(uint64(length)))
	out, err := hkdf.Expand(s.newHash(), prk, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("%w: EDHOC_KDF: %w", ErrMessageFormat, err)
	}
	return out, nil
}

func newAEAD(k aeadKind, key []byte) (cipher.AEAD, error) {
	switch k {
	case aeadCCM8:
		return aesccm.New(key, 8, 13)
	case aeadCCM16:
		return aesccm.New(key, 16, 13)
	case aeadGCM128, aeadGCM256:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	case aeadChaCha:
		return chacha20poly1305.New(key)
	}
	return nil, ErrUnsupportedSuite
}

func cosePublic(k aeadKind) cose.Algorithm {
	switch k {
	case aeadGCM128:
		return coseA128GCM
	case aeadGCM256:
		return coseA256GCM
	case aeadChaCha:
		return coseChaCha20
	default:
		return coseAESCCM1664128
	}
}

// ellipticCurve returns the crypto/elliptic parameters for P-curves.
func (s *rfcSuite) ellipticCurve() elliptic.Curve {
	switch s.curve {
	case ecdh.P256():
		return elliptic.P256()
	case ecdh.P384():
		return elliptic.P384()
	}
	return nil
}
