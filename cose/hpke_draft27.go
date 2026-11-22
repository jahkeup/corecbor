// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
	"slices"

	"github.com/jahkeup/corecbor"
)

// COSE-HPKE (draft-ietf-cose-hpke-27).
//
// Experimental: everything in this file implements
// draft-ietf-cose-hpke-27, which has not been published as an RFC. Its
// algorithm identifiers and header labels are the draft's "Assumed"
// values (HPKE-0 = 35 … HPKE-7-KE = 53, ek = -4, psk_id = -5); IANA
// assigns the real ones on publication, and they WILL change. Every
// entry point returns ErrUnsupportedAlgorithm unless WithDraftHPKE27 is
// passed, and the selector is renamed (not aliased) when the RFC is
// published (proposal 034).

const (
	headerLabelHPKEEncapsulatedKey int64 = -4 // "ek", draft-27 §7.3.1 (assumed)
	headerLabelHPKEPSKID           int64 = -5 // "psk_id", draft-27 §7.3.2 (assumed)

	hpkeRecipientContext = "HPKE Recipient" // draft-27 §3.3.1
)

// WithDraftHPKE27 enables COSE-HPKE as specified by
// draft-ietf-cose-hpke-27: HPKESeal, HPKEOpen and HPKERecipient.
//
// Experimental: implements draft-ietf-cose-hpke-27. Code points are the
// draft's assumed values and WILL change when IANA assigns them; this
// selector is then renamed, per proposal 034.
func WithDraftHPKE27() EncryptOption {
	return func(o *encryptOpts) { o.legacy.draftHPKE27 = true }
}

// WithHPKEInfo sets the HPKE info parameter for integrated encryption
// (HPKESeal/HPKEOpen); it defaults to the empty string (draft-27 §3.2).
// Key encryption binds context through HPKERecipient.ExtraInfo instead.
//
// Experimental: part of the draft-ietf-cose-hpke-27 support.
func WithHPKEInfo(info []byte) EncryptOption {
	return func(o *encryptOpts) { o.hpkeInfo = info }
}

// HPKESuite is a COSE-HPKE ciphersuite (draft-ietf-cose-hpke-27 §4).
// Each suite has an integrated-encryption algorithm (for COSE_Encrypt0)
// and a key-encryption algorithm (for a COSE_Recipient).
//
// Experimental: part of the draft-ietf-cose-hpke-27 support.
type HPKESuite int

const (
	HPKE0 HPKESuite = iota // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
	HPKE1                  // DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM
	HPKE2                  // DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM
	HPKE3                  // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
	HPKE4                  // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
	HPKE5                  // DHKEM(X448, HKDF-SHA512), HKDF-SHA512, AES-256-GCM (unsupported: no X448 in Go)
	HPKE6                  // DHKEM(X448, HKDF-SHA512), HKDF-SHA512, ChaCha20Poly1305 (unsupported: no X448 in Go)
	HPKE7                  // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
)

type hpkeSuiteParams struct {
	integrated, keyEncryption Algorithm // draft-27 assumed values
	curve                     ecdh.Curve
	coseCurve                 Curve
	kdf                       func() hpke.KDF
	aead                      func() hpke.AEAD
}

var hpkeSuites = [...]hpkeSuiteParams{
	HPKE0: {35, 46, ecdh.P256(), CurveP256, hpke.HKDFSHA256, hpke.AES128GCM},
	HPKE1: {37, 47, ecdh.P384(), CurveP384, hpke.HKDFSHA384, hpke.AES256GCM},
	HPKE2: {39, 48, ecdh.P521(), CurveP521, hpke.HKDFSHA512, hpke.AES256GCM},
	HPKE3: {41, 49, ecdh.X25519(), CurveX25519, hpke.HKDFSHA256, hpke.AES128GCM},
	HPKE4: {42, 50, ecdh.X25519(), CurveX25519, hpke.HKDFSHA256, hpke.ChaCha20Poly1305},
	HPKE5: {43, 51, nil, CurveX448, hpke.HKDFSHA512, hpke.AES256GCM},
	HPKE6: {44, 52, nil, CurveX448, hpke.HKDFSHA512, hpke.ChaCha20Poly1305},
	HPKE7: {45, 53, ecdh.P256(), CurveP256, hpke.HKDFSHA256, hpke.AES256GCM},
}

// String returns the draft's ciphersuite label, such as "HPKE-0".
func (s HPKESuite) String() string {
	if s < HPKE0 || s > HPKE7 {
		return fmt.Sprintf("HPKESuite(%d)", int(s))
	}
	return fmt.Sprintf("HPKE-%d", int(s))
}

// IntegratedAlgorithm returns the suite's integrated-encryption
// algorithm identifier (draft-27 assumed value, e.g. 35 for HPKE-0).
func (s HPKESuite) IntegratedAlgorithm() Algorithm {
	if p, ok := s.params(); ok {
		return p.integrated
	}
	return 0
}

// KeyEncryptionAlgorithm returns the suite's key-encryption algorithm
// identifier (draft-27 assumed value, e.g. 46 for HPKE-0-KE).
func (s HPKESuite) KeyEncryptionAlgorithm() Algorithm {
	if p, ok := s.params(); ok {
		return p.keyEncryption
	}
	return 0
}

func (s HPKESuite) params() (hpkeSuiteParams, bool) {
	if s < HPKE0 || s > HPKE7 {
		return hpkeSuiteParams{}, false
	}
	return hpkeSuites[s], true
}

// usable returns the suite's parameters, or ErrUnsupportedAlgorithm for
// an unknown suite or one whose KEM this build can't run.
func (s HPKESuite) usable() (hpkeSuiteParams, error) {
	p, ok := s.params()
	if !ok {
		return hpkeSuiteParams{}, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, s)
	}
	if p.curve == nil {
		return hpkeSuiteParams{}, fmt.Errorf("%w: %s needs X448, which Go doesn't implement", ErrUnsupportedAlgorithm, s)
	}
	return p, nil
}

// hpkeSuiteFor maps an algorithm identifier to its suite; ke selects the
// key-encryption identifiers instead of the integrated ones.
func hpkeSuiteFor(alg Algorithm, ke bool) (HPKESuite, bool) {
	for s := HPKE0; s <= HPKE7; s++ {
		p := hpkeSuites[s]
		if (!ke && p.integrated == alg) || (ke && p.keyEncryption == alg) {
			return s, true
		}
	}
	return 0, false
}

func requireDraftHPKE27(legacy legacyEncoding) error {
	if !legacy.draftHPKE27 {
		return fmt.Errorf("%w: COSE-HPKE requires WithDraftHPKE27 (draft-ietf-cose-hpke-27)", ErrUnsupportedAlgorithm)
	}
	return nil
}

// HPKESeal encrypts plaintext into a COSE_Encrypt0 for recipient using
// HPKE integrated encryption (draft-27 §3.2) in mode_base. The
// protected bucket carries the suite's algorithm and, when the key has
// one, its kid; the encapsulated key goes in the unprotected "ek"
// header. WithEncryptExternalAAD and WithHPKEInfo bind external data.
// It needs WithDraftHPKE27.
//
// Experimental: implements draft-ietf-cose-hpke-27.
func HPKESeal(plaintext []byte, recipient *Key, suite HPKESuite, opts ...EncryptOption) (*Encrypt0, error) {
	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}
	if err := requireDraftHPKE27(o.legacy); err != nil {
		return nil, err
	}
	p, err := suite.usable()
	if err != nil {
		return nil, err
	}
	pub, err := hpkePublicKey(recipient, p, p.integrated)
	if err != nil {
		return nil, err
	}
	msg := &Encrypt0{}
	msg.Protected.SetAlgorithm(p.integrated)
	if kid := recipient.ID(); kid != nil {
		setParam(&msg.Protected, headerLabelKeyID, bytes.Clone(kid))
	}
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	aad, err := buildEncStructure(protectedBytes, o.externalAAD)
	if err != nil {
		return nil, err
	}
	enc, sender, err := hpke.NewSender(pub, p.kdf(), p.aead(), o.hpkeInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: HPKE setup: %w", ErrInvalidKey, err)
	}
	ct, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("cose: HPKE seal: %w", err)
	}
	setParam(&msg.Unprotected, headerLabelHPKEEncapsulatedKey, enc)
	msg.Ciphertext = ct
	return msg, nil
}

// HPKEOpen decrypts a COSE_Encrypt0 produced with HPKE integrated
// encryption (draft-27 §3.2) using recipient's private key. The suite
// comes from the protected alg, which must be a COSE-HPKE integrated
// identifier (and in WithEncryptAlgorithms, when given). mode_psk
// (a psk_id header) is ErrUnsupportedAlgorithm: Go's crypto/hpke
// implements mode_base only. It needs WithDraftHPKE27.
//
// Experimental: implements draft-ietf-cose-hpke-27.
func HPKEOpen(msg *Encrypt0, recipient *Key, opts ...EncryptOption) ([]byte, error) {
	var o encryptOpts
	for _, opt := range opts {
		opt(&o)
	}
	if err := requireDraftHPKE27(o.legacy); err != nil {
		return nil, err
	}
	if err := checkCrit(&msg.Protected, &msg.Unprotected, &o.policy); err != nil {
		return nil, err
	}
	alg, loc, err := headerAlg(&msg.Protected, &msg.Unprotected)
	if err != nil {
		return nil, err
	}
	if loc != algProtected {
		return nil, fmt.Errorf("%w: COSE-HPKE alg must be in the protected bucket", ErrAlgorithmMismatch)
	}
	suite, ok := hpkeSuiteFor(alg, false)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a COSE-HPKE integrated encryption algorithm", ErrAlgorithmMismatch, alg)
	}
	if o.policy.allowed != nil && !slices.Contains(o.policy.allowed, alg) {
		return nil, fmt.Errorf("%w: %s not in allowed algorithms", ErrAlgorithmMismatch, alg)
	}
	if _, psk := msg.Protected.params[headerLabelHPKEPSKID]; psk {
		return nil, fmt.Errorf("%w: COSE-HPKE mode_psk (psk_id present)", ErrUnsupportedAlgorithm)
	}
	p, err := suite.usable()
	if err != nil {
		return nil, err
	}
	enc, ok := msg.Unprotected.params[headerLabelHPKEEncapsulatedKey].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: missing ek header", ErrDecryption)
	}
	priv, err := hpkePrivateKey(recipient, p, alg)
	if err != nil {
		return nil, err
	}
	if msg.Ciphertext == nil {
		return nil, fmt.Errorf("%w: detached ciphertext", ErrDecryption)
	}
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	aad, err := buildEncStructure(protectedBytes, o.externalAAD)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, priv, p.kdf(), p.aead(), o.hpkeInfo)
	if err != nil {
		return nil, ErrDecryption
	}
	plaintext, err := r.Open(aad, msg.Ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// HPKERecipient is a COSE-HPKE key-encryption recipient
// (draft-27 §3.3) for EncryptMulti and DecryptMulti, in mode_base. It
// needs WithDraftHPKE27 on the call.
//
// Experimental: implements draft-ietf-cose-hpke-27.
type HPKERecipient struct {
	// Suite selects the ciphersuite; the recipient's alg is its
	// key-encryption identifier (e.g. HPKE-0-KE).
	Suite HPKESuite
	// PublicKey is the recipient's KEM public key (EncryptMulti).
	PublicKey *Key
	// PrivateKey is the recipient's KEM private key (DecryptMulti).
	PrivateKey *Key
	// KeyID, when set, is written as a protected kid so it is bound
	// into the HPKE key schedule (RECOMMENDED by draft-27 §3.3.2).
	KeyID []byte
	// PSK and PSKID select mode_psk. Go's crypto/hpke implements
	// mode_base only, so setting either is ErrUnsupportedAlgorithm.
	PSK, PSKID []byte
	// ExtraInfo is the Recipient_structure's recipient_extra_info:
	// context both sides know that is bound but not transmitted.
	ExtraInfo []byte
	// AAD is the HPKE AAD for the key wrap; draft-27 says it SHOULD be
	// empty.
	AAD []byte
}

// Algorithm returns the suite's key-encryption identifier.
func (h *HPKERecipient) Algorithm() Algorithm { return h.Suite.KeyEncryptionAlgorithm() }

// recipientLayer writes the recipient's protected bucket: alg and, when
// set, kid (draft-27 §3.3.2).
func (h *HPKERecipient) recipientLayer(alg Algorithm) (Headers, []byte, error) {
	var prot Headers
	prot.SetAlgorithm(alg)
	if h.KeyID != nil {
		setParam(&prot, headerLabelKeyID, bytes.Clone(h.KeyID))
	}
	b, err := prot.encodeProtected()
	if err != nil {
		return Headers{}, nil, err
	}
	prot.raw = b
	return prot, b, nil
}

func (h *HPKERecipient) checkMode() error {
	if h.PSK != nil || h.PSKID != nil {
		return fmt.Errorf("%w: COSE-HPKE mode_psk", ErrUnsupportedAlgorithm)
	}
	return nil
}

// WrapKey encrypts cek to PublicKey with HPKE, using the
// Recipient_structure as info, and returns the "ek" header.
func (h *HPKERecipient) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	if err := requireDraftHPKE27(opts.legacy); err != nil {
		return nil, Headers{}, err
	}
	if err := h.checkMode(); err != nil {
		return nil, Headers{}, err
	}
	p, err := h.Suite.usable()
	if err != nil {
		return nil, Headers{}, err
	}
	pub, err := hpkePublicKey(h.PublicKey, p, p.keyEncryption)
	if err != nil {
		return nil, Headers{}, err
	}
	info, err := hpkeRecipientStructure(opts.CEKAlgorithm, []byte(opts.protected), h.ExtraInfo)
	if err != nil {
		return nil, Headers{}, err
	}
	enc, sender, err := hpke.NewSender(pub, p.kdf(), p.aead(), info)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: HPKE setup: %w", ErrInvalidKey, err)
	}
	ct, err := sender.Seal(h.AAD, cek)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("cose: HPKE seal: %w", err)
	}
	var hdrs Headers
	setParam(&hdrs, headerLabelHPKEEncapsulatedKey, enc)
	return ct, hdrs, nil
}

// UnwrapKey recovers the CEK with PrivateKey from the recipient's "ek"
// header and ciphertext.
func (h *HPKERecipient) UnwrapKey(ciphertext []byte, hdrs Headers, opts KeyUnwrapOpts) ([]byte, error) {
	if err := requireDraftHPKE27(opts.legacy); err != nil {
		return nil, err
	}
	if err := h.checkMode(); err != nil {
		return nil, err
	}
	p, err := h.Suite.usable()
	if err != nil {
		return nil, err
	}
	prot, err := decodeProtected([]byte(opts.protected), DecodeLimits{})
	if err != nil {
		return nil, err
	}
	if _, psk := prot.params[headerLabelHPKEPSKID]; psk {
		return nil, fmt.Errorf("%w: COSE-HPKE mode_psk (psk_id present)", ErrUnsupportedAlgorithm)
	}
	enc, ok := hdrs.params[headerLabelHPKEEncapsulatedKey].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: missing ek header", ErrDecryption)
	}
	priv, err := hpkePrivateKey(h.PrivateKey, p, p.keyEncryption)
	if err != nil {
		return nil, err
	}
	info, err := hpkeRecipientStructure(opts.CEKAlgorithm, []byte(opts.protected), h.ExtraInfo)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, priv, p.kdf(), p.aead(), info)
	if err != nil {
		return nil, ErrDecryption
	}
	cek, err := r.Open(h.AAD, ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}
	if opts.CEKLength != 0 && len(cek) != opts.CEKLength {
		return nil, fmt.Errorf("%w: CEK is %d bytes, want %d", ErrDecryption, len(cek), opts.CEKLength)
	}
	return cek, nil
}

// hpkeRecipientStructure encodes the Recipient_structure (draft-27
// §3.3.1) deterministically:
// ["HPKE Recipient", next_layer_alg, recipient_protected_header, recipient_extra_info].
func hpkeRecipientStructure(nextLayer Algorithm, protected, extraInfo []byte) ([]byte, error) {
	if protected == nil {
		protected = []byte{}
	}
	if extraInfo == nil {
		extraInfo = []byte{}
	}
	return sharedEncoder.Encode(nil, corecbor.MakeArray(
		corecbor.Text(hpkeRecipientContext),
		algValueCBOR(nextLayer),
		corecbor.Bytes(protected),
		corecbor.Bytes(extraInfo),
	))
}

func algValueCBOR(a Algorithm) corecbor.Value {
	if a >= 0 {
		return corecbor.Uint(uint64(a))
	}
	return corecbor.NegInt(uint64(-1 - int64(a)))
}

// hpkeKeyCheck applies draft-27 §3.4/§4.1 to a COSE_Key for a suite: a
// matching kty/crv, and an alg (when present) equal to want.
func hpkeKeyCheck(k *Key, p hpkeSuiteParams, want Algorithm) error {
	if k == nil {
		return fmt.Errorf("%w: nil HPKE key", ErrInvalidKey)
	}
	if a, ok := k.Algorithm(); ok && a != want {
		return fmt.Errorf("%w: key alg %s, suite uses %s", ErrAlgorithmMismatch, a, want)
	}
	if k.Curve() != p.coseCurve {
		return fmt.Errorf("%w: key curve %d, suite needs %d", ErrInvalidKey, k.Curve(), p.coseCurve)
	}
	return nil
}

func hpkePublicKey(k *Key, p hpkeSuiteParams, want Algorithm) (hpke.PublicKey, error) {
	if err := hpkeKeyCheck(k, p, want); err != nil {
		return nil, err
	}
	pub, err := ecdhPublic(k, p.curve)
	if err != nil {
		return nil, err
	}
	hp, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return hp, nil
}

func hpkePrivateKey(k *Key, p hpkeSuiteParams, want Algorithm) (hpke.PrivateKey, error) {
	if err := hpkeKeyCheck(k, p, want); err != nil {
		return nil, err
	}
	if ops := k.Ops(); ops != nil && !k.Permits(KeyOpDeriveBits) {
		return nil, fmt.Errorf("%w: key_ops don't permit derive bits", ErrInvalidKey)
	}
	d, ok := k.bytesParam(keyLabelD)
	if !ok {
		return nil, fmt.Errorf("%w: HPKE private key has no d", ErrInvalidKey)
	}
	priv, err := p.curve.NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if pub, err := ecdhPublic(k, p.curve); err == nil && !pub.Equal(priv.PublicKey()) {
		return nil, fmt.Errorf("%w: HPKE private key doesn't match its public key", ErrInvalidKey)
	}
	hp, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return hp, nil
}

// ecdhPublic returns k's public key as an *ecdh.PublicKey on curve.
func ecdhPublic(k *Key, curve ecdh.Curve) (*ecdh.PublicKey, error) {
	pub, err := k.ECDHPublicKey()
	if err != nil {
		return nil, fmt.Errorf("%w: not a KEM key: %w", ErrInvalidKey, err)
	}
	if pub.Curve() != curve {
		return nil, fmt.Errorf("%w: wrong curve for suite", ErrInvalidKey)
	}
	return pub, nil
}
