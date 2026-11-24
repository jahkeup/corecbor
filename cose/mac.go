// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"slices"

	"github.com/jahkeup/corecbor"
)

type MACOption func(*macOpts)

type macOpts struct {
	externalAAD []byte
	policy      headerPolicy
	shortKey    bool // InsecureAllowShortMACKeys

	allowProtRecipient bool // AllowMACProtectedRecipientHeaders
	legacy             legacyEncoding
}

func WithMACExternalAAD(aad []byte) MACOption {
	return func(o *macOpts) { o.externalAAD = aad }
}

// WithMACAlgorithms restricts which MAC algorithms are accepted. For
// VerifyMAC0 the caller's alg must be listed. For VerifyMACMulti it
// replaces the default set (HMAC 256/256, 384/384, 512/512); list
// AlgHMAC256_64 here to accept the 64-bit truncated tag.
func WithMACAlgorithms(algs ...Algorithm) MACOption {
	return func(o *macOpts) { o.policy.allowed = slices.Clone(algs) }
}

// WithMACKnownCriticalHeaders declares header labels the caller
// processes itself; see WithKnownCriticalHeaders.
func WithMACKnownCriticalHeaders(labels ...any) MACOption {
	return func(o *macOpts) { o.policy.knownCrit = append(o.policy.knownCrit, normalizeLabels(labels)...) }
}

// WithStrictMACKeyLength requires the HMAC key to be at least as long as
// the hash output (RFC 9053 §3.1). That is the default since v0.3, so this option changes nothing; it
// undoes an earlier
// InsecureAllowShortMACKeys in the same option list.
func WithStrictMACKeyLength() MACOption {
	return func(o *macOpts) { o.shortKey = false }
}

// InsecureAllowShortMACKeys accepts an HMAC key shorter than the hash
// output (32 bytes for HMAC 256/64 and 256/256, 48 for 384/384, 64 for
// 512/512), which RFC 9053 §3.1 says the key should be, for keys
// provisioned before this check became the default. A short key lowers
// the strength of every tag made with it. An empty key is still
// ErrInvalidKey.
func InsecureAllowShortMACKeys() MACOption {
	return func(o *macOpts) { o.shortKey = true }
}

// AllowMACEmptyProtectedAsReceived is AllowEmptyProtectedAsReceived for
// VerifyMAC0 and VerifyMACMulti (the MAC_structure).
func AllowMACEmptyProtectedAsReceived() MACOption {
	return func(o *macOpts) { o.policy.emptyAsReceived = true }
}

// RequireMACProtectedAlgorithm is RequireProtectedAlgorithm for
// VerifyMAC0 (VerifyMACMulti always requires a protected alg).
func RequireMACProtectedAlgorithm() MACOption {
	return func(o *macOpts) { o.policy.requireProtectedAlg = true }
}

// AllowMACProtectedRecipientHeaders is AllowProtectedRecipientHeaders
// for VerifyMACMulti.
func AllowMACProtectedRecipientHeaders() MACOption {
	return func(o *macOpts) { o.allowProtRecipient = true }
}

// WithLegacyMACPBES2Labels reads and writes PBES2 COSE_Mac recipients
// with the v0.2 identifiers (-11, count in -21), as
// WithLegacyPBES2Labels does for COSE_Encrypt. It weakens no
// verification. There is no MAC counterpart to WithLegacyECDHES: v0.2
// ECDH-ES MAC recipients discarded the MAC key and never verified.
//
// Deprecated: interop with corecbor v0.2 only; removed
// no earlier than v0.5.0.
func WithLegacyMACPBES2Labels() MACOption {
	return func(o *macOpts) { o.legacy.pbes2 = true }
}

// WithLegacyMACHeaders restores v0.2.2 header handling for MAC
// verification: the alg header isn't bound to the caller's algorithm
// (VerifyMAC0) or checked against the unprotected bucket
// (VerifyMACMulti), and crit isn't processed. It does not re-enable
// header-selected HMAC 256/64 in VerifyMACMulti; use WithMACAlgorithms.
//
// Deprecated: ignores the header alg and crit (RFC 9052 §3.1). Retained
// for migration only; removed no earlier than v0.5.0.
func WithLegacyMACHeaders() MACOption {
	return func(o *macOpts) {
		o.policy.legacyAlg = true
		o.policy.legacyCrit = true
	}
}

// checkMACKey rejects an empty key (a MAC under it authenticates
// nothing) and, unless InsecureAllowShortMACKeys, one shorter than the
// hash output (RFC 9053 §3.1).
func (o *macOpts) checkMACKey(key []byte, alg Algorithm) error {
	if len(key) == 0 {
		return fmt.Errorf("%w: empty MAC key", ErrInvalidKey)
	}
	if !o.shortKey && len(key) < hmacKeyLen(alg) {
		return fmt.Errorf("%w: %s key is %d bytes, must be at least %d (RFC 9053 §3.1; see InsecureAllowShortMACKeys)", ErrInvalidKey, alg, len(key), hmacKeyLen(alg))
	}
	return nil
}

func ComputeMAC0(payload, key []byte, alg Algorithm, opts ...MACOption) (*Mac0, error) {
	var o macOpts
	for _, opt := range opts {
		opt(&o)
	}

	hashFunc, err := hmacHashFunc(alg)
	if err != nil {
		return nil, err
	}
	if err := o.checkMACKey(key, alg); err != nil {
		return nil, err
	}

	msg := &Mac0{Payload: payload}
	msg.Protected.SetAlgorithm(alg)

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	toMAC, err := buildMACStructure(protectedBytes, o.externalAAD, payload)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(hashFunc, key)
	mac.Write(toMAC)
	tag := mac.Sum(nil)

	if alg == AlgHMAC256_64 {
		tag = tag[:8]
	}

	msg.Tag = tag
	return msg, nil
}

// VerifyMAC0 verifies a COSE_Mac0 tag. A nil msg.Payload means the
// payload is detached (RFC 9052 §2); set it before calling, or
// VerifyMAC0 returns ErrMissingPayload.
func VerifyMAC0(msg *Mac0, key []byte, alg Algorithm, opts ...MACOption) error {
	if msg.Payload == nil {
		return ErrMissingPayload
	}
	var o macOpts
	for _, opt := range opts {
		opt(&o)
	}

	hashFunc, err := hmacHashFunc(alg)
	if err != nil {
		return err
	}
	if err := checkCrit(&msg.Protected, &msg.Unprotected, &o.policy); err != nil {
		return err
	}
	if err := bindAlg(&msg.Protected, &msg.Unprotected, alg, &o.policy); err != nil {
		return err
	}
	if err := o.checkMACKey(key, alg); err != nil {
		return err
	}

	protectedBytes, err := msg.Protected.authProtected(&o.policy)
	if err != nil {
		return err
	}

	toMAC, err := buildMACStructure(protectedBytes, o.externalAAD, msg.Payload)
	if err != nil {
		return err
	}

	mac := hmac.New(hashFunc, key)
	mac.Write(toMAC)
	expected := mac.Sum(nil)

	if alg == AlgHMAC256_64 {
		expected = expected[:8]
	}

	if subtle.ConstantTimeCompare(msg.Tag, expected) != 1 {
		return ErrMACVerification
	}
	return nil
}

// MAC_structure = ["MAC0", protectedBstr, externalAAD, payload]  (RFC 9052 §6.3)
func buildMACStructure(protectedBytes, externalAAD, payload []byte) ([]byte, error) {
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	if payload == nil {
		payload = []byte{}
	}
	arr := corecbor.MakeArray(
		corecbor.Text("MAC0"),
		corecbor.Bytes(protectedBytes),
		corecbor.Bytes(externalAAD),
		corecbor.Bytes(payload),
	)
	enc := sharedEncoder
	return enc.Encode(nil, arr)
}

func hmacHashFunc(alg Algorithm) (func() hash.Hash, error) {
	switch alg {
	case AlgHMAC256_64, AlgHMAC256:
		return sha256.New, nil
	case AlgHMAC384:
		return sha512.New384, nil
	case AlgHMAC512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: %s is not an HMAC algorithm", ErrUnsupportedAlgorithm, alg)
	}
}
