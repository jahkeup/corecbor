// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose/internal/aeskw"
)

const (
	headerLabelEphemeralKey int64 = -1
	headerLabelSalt         int64 = -20

	// Context algorithm parameters (RFC 9053 §5.2, Table 10).
	headerLabelPartyUIdentity int64 = -21
	headerLabelPartyUNonce    int64 = -22
	headerLabelPartyUOther    int64 = -23
	headerLabelPartyVIdentity int64 = -24
	headerLabelPartyVNonce    int64 = -25
	headerLabelPartyVOther    int64 = -26
)

// PartyInfo is one party's entry in the ECDH key-derivation context
// (RFC 9053 §5.2). Nil fields are encoded as CBOR null. Non-empty
// fields are also carried in the recipient's unprotected headers
// (labels -21 to -26), and values received there take precedence.
type PartyInfo struct {
	Identity []byte
	Nonce    []byte
	Other    []byte
}

// KeyAgreer is implemented by KeyDerivers whose algorithm is direct key
// agreement (RFC 9052 §8.5.4): the agreed key is the content key, so
// the recipient carries no ciphertext and must be the only recipient.
// EncryptMulti and ComputeMACMulti use it when their only recipient's
// algorithm is ECDH-ES + HKDF (-25, -26).
type KeyAgreer interface {
	AgreeKey(opts KeyWrapOpts) (cek []byte, headers Headers, err error)
}

// ECDHESKey is an ECDH-ES recipient (RFC 9053 §6.3, §6.4) with an
// ephemeral sender key: PeerPublic is the recipient's static key when
// sealing, PrivateKey is the recipient's private key when opening. Both
// P-256/384/521 and X25519 keys work.
//
// Alg selects the variant; its zero value is ECDH-ES + HKDF-256 (-25),
// the algorithm ECDHESKey has always reported:
//   - -25 / -26: direct key agreement with HKDF-SHA-256 / -512; the
//     derived key is the content key, so the recipient must be the only
//     one.
//   - -29 / -30 / -31: HKDF-SHA-256 derives a 128/192/256-bit KEK that
//     AES-KW-wraps the content key.
//
// v0.2 performed AES-KW under -25 with a raw-point ephemeral key, which
// no other implementation understands; WithLegacyECDHES restores that
// encoding.
type ECDHESKey struct {
	PrivateKey *ecdh.PrivateKey
	PeerPublic *ecdh.PublicKey

	// Alg is the ECDH-ES algorithm; zero means AlgECDH_ES_HKDF_256.
	Alg Algorithm
	// KDF holds optional key-derivation inputs; nil means none.
	KDF *ECDHKDFContext
}

// ECDHKDFContext holds the optional inputs to ECDH-ES key derivation
// (RFC 9053 §5): the PartyU and PartyV context entries, and the HKDF
// salt (header -20), where nil means none. It is a separate struct, held
// by pointer, so that ECDHESKey stays comparable.
type ECDHKDFContext struct {
	PartyU, PartyV PartyInfo
	Salt           []byte
}

// kdf returns e's key-derivation inputs, or the zero context.
func (e *ECDHESKey) kdf() ECDHKDFContext {
	if e.KDF == nil {
		return ECDHKDFContext{}
	}
	return *e.KDF
}

func (e *ECDHESKey) Algorithm() Algorithm {
	if e.Alg == 0 {
		return AlgECDH_ES_HKDF_256
	}
	return e.Alg
}

// ecdhVariant describes one ECDH-ES algorithm.
type ecdhVariant struct {
	hash    func() hash.Hash
	wrapAlg Algorithm // 0 for direct key agreement
	kekLen  int       // KEK length for key-wrap variants
}

func ecdhVariantFor(alg Algorithm) (ecdhVariant, error) {
	switch alg {
	case AlgECDH_ES_HKDF_256:
		return ecdhVariant{hash: sha256.New}, nil
	case AlgECDH_ES_HKDF_512:
		return ecdhVariant{hash: sha512.New}, nil
	case AlgECDH_ES_A128KW:
		return ecdhVariant{hash: sha256.New, wrapAlg: AlgA128KW, kekLen: 16}, nil
	case AlgECDH_ES_A192KW:
		return ecdhVariant{hash: sha256.New, wrapAlg: AlgA192KW, kekLen: 24}, nil
	case AlgECDH_ES_A256KW:
		return ecdhVariant{hash: sha256.New, wrapAlg: AlgA256KW, kekLen: 32}, nil
	}
	return ecdhVariant{}, fmt.Errorf("%w: %s is not an ECDH-ES algorithm", ErrUnsupportedAlgorithm, alg)
}

func isDirectKeyAgreement(alg Algorithm) bool {
	return alg == AlgECDH_ES_HKDF_256 || alg == AlgECDH_ES_HKDF_512
}

// AgreeKey performs direct key agreement (-25/-26): it generates an
// ephemeral key, derives the content key from ECDH with PeerPublic, and
// returns the headers to send (ephemeral key, salt, party info).
func (e *ECDHESKey) AgreeKey(opts KeyWrapOpts) ([]byte, Headers, error) {
	alg := e.Algorithm()
	if !isDirectKeyAgreement(alg) {
		return nil, Headers{}, fmt.Errorf("%w: %s is not direct key agreement", ErrUnsupportedAlgorithm, alg)
	}
	v, _ := ecdhVariantFor(alg)
	keyLen := opts.CEKLength
	if keyLen == 0 {
		keyLen = cekLenForAlg(opts.CEKAlgorithm)
	}
	if keyLen == 0 {
		return nil, Headers{}, fmt.Errorf("%w: cannot determine content key length", ErrInvalidKey)
	}
	shared, h, err := e.ephemeralAgreement()
	if err != nil {
		return nil, Headers{}, err
	}
	key, err := e.derive(v, shared, opts.CEKAlgorithm, keyLen, opts.protected, Headers{})
	if err != nil {
		return nil, Headers{}, err
	}
	return key, h, nil
}

// WrapKey wraps cek for a key-wrap variant (-29/-30/-31). Direct
// variants have nothing to wrap and return ErrUnsupportedAlgorithm; use
// the ECDHESKey as the only recipient so AgreeKey is used.
func (e *ECDHESKey) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	alg := e.Algorithm()
	if opts.legacy.ecdh && alg == AlgECDH_ES_HKDF_256 {
		return e.legacyWrap(cek, opts)
	}
	v, err := ecdhVariantFor(alg)
	if err != nil {
		return nil, Headers{}, err
	}
	if v.wrapAlg == 0 {
		return nil, Headers{}, fmt.Errorf("%w: %s is direct key agreement and must be the only recipient", ErrUnsupportedAlgorithm, alg)
	}
	shared, h, err := e.ephemeralAgreement()
	if err != nil {
		return nil, Headers{}, err
	}
	kek, err := e.derive(v, shared, v.wrapAlg, v.kekLen, opts.protected, Headers{})
	if err != nil {
		return nil, Headers{}, err
	}
	wrapped, err := aeskw.Wrap(kek, cek)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return wrapped, h, nil
}

// UnwrapKey recovers the content key: for direct variants the derived
// key itself (the recipient ciphertext must be empty), for key-wrap
// variants the AES-KW-unwrapped key.
func (e *ECDHESKey) UnwrapKey(ciphertext []byte, h Headers, opts KeyUnwrapOpts) ([]byte, error) {
	if e.PrivateKey == nil {
		return nil, fmt.Errorf("%w: ECDHESKey.PrivateKey is nil", ErrInvalidKey)
	}
	alg := e.Algorithm()
	if raw, ok := h.Get(headerLabelEphemeralKey).([]byte); ok {
		// v0.2 sent the ephemeral key as raw point bytes (RFC 9053
		// §6.3.1 requires a COSE_Key).
		if !opts.legacy.ecdh || alg != AlgECDH_ES_HKDF_256 {
			return nil, fmt.Errorf("%w: raw-point ephemeral key (v0.2 encoding; see WithLegacyECDHES)", ErrUnsupportedAlgorithm)
		}
		return e.legacyUnwrap(raw, ciphertext, opts)
	}
	v, err := ecdhVariantFor(alg)
	if err != nil {
		return nil, err
	}
	peer, err := ephemeralFromHeaders(h, e.PrivateKey.Curve())
	if err != nil {
		return nil, err
	}
	shared, err := e.PrivateKey.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %w", ErrDecryption, err)
	}
	if v.wrapAlg == 0 {
		if len(ciphertext) != 0 {
			return nil, fmt.Errorf("%w: direct key agreement recipient carries ciphertext", ErrMalformed)
		}
		keyLen := opts.CEKLength
		if keyLen == 0 {
			keyLen = cekLenForAlg(opts.CEKAlgorithm)
		}
		if keyLen == 0 {
			return nil, fmt.Errorf("%w: cannot determine content key length", ErrDecryption)
		}
		return e.derive(v, shared, opts.CEKAlgorithm, keyLen, opts.protected, h)
	}
	kek, err := e.derive(v, shared, v.wrapAlg, v.kekLen, opts.protected, h)
	if err != nil {
		return nil, err
	}
	cek, kerr := aeskw.Unwrap(kek, ciphertext)
	if kerr != nil {
		return nil, ErrDecryption
	}
	return cek, nil
}

// ephemeralAgreement generates an ephemeral key on PeerPublic's curve
// and returns the shared secret and the recipient headers to send: the
// ephemeral key as a COSE_Key, and any salt and party information.
func (e *ECDHESKey) ephemeralAgreement() ([]byte, Headers, error) {
	if e.PeerPublic == nil {
		return nil, Headers{}, fmt.Errorf("%w: ECDHESKey.PeerPublic is nil", ErrInvalidKey)
	}
	ephemeral, err := e.PeerPublic.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: generating ephemeral key: %w", ErrInvalidKey, err)
	}
	shared, err := ephemeral.ECDH(e.PeerPublic)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: ECDH failed: %w", ErrInvalidKey, err)
	}
	epk, err := ephemeralCOSEKey(ephemeral.PublicKey())
	if err != nil {
		return nil, Headers{}, err
	}
	c := e.kdf()
	params := map[any]any{headerLabelEphemeralKey: epk}
	for label, v := range map[int64][]byte{
		headerLabelSalt:           c.Salt,
		headerLabelPartyUIdentity: c.PartyU.Identity,
		headerLabelPartyUNonce:    c.PartyU.Nonce,
		headerLabelPartyUOther:    c.PartyU.Other,
		headerLabelPartyVIdentity: c.PartyV.Identity,
		headerLabelPartyVNonce:    c.PartyV.Nonce,
		headerLabelPartyVOther:    c.PartyV.Other,
	} {
		if len(v) > 0 {
			params[label] = v
		}
	}
	return shared, Headers{params: params}, nil
}

// derive runs HKDF over the shared secret with the COSE_KDF_Context for
// algID and keyLen bytes (RFC 9053 §5.1-5.2). protected is the
// recipient's protected bucket. Salt and party values in h (received
// headers) take precedence over the ECDHESKey's own.
func (e *ECDHESKey) derive(v ecdhVariant, shared []byte, algID Algorithm, keyLen int, protected string, h Headers) ([]byte, error) {
	c := e.kdf()
	pick := func(label int64, own []byte) []byte {
		if b, ok := h.Get(label).([]byte); ok {
			return b
		}
		return own
	}
	partyU := PartyInfo{
		Identity: pick(headerLabelPartyUIdentity, c.PartyU.Identity),
		Nonce:    pick(headerLabelPartyUNonce, c.PartyU.Nonce),
		Other:    pick(headerLabelPartyUOther, c.PartyU.Other),
	}
	partyV := PartyInfo{
		Identity: pick(headerLabelPartyVIdentity, c.PartyV.Identity),
		Nonce:    pick(headerLabelPartyVNonce, c.PartyV.Nonce),
		Other:    pick(headerLabelPartyVOther, c.PartyV.Other),
	}
	info, err := kdfContext(algID, keyLen, []byte(protected), partyU, partyV)
	if err != nil {
		return nil, err
	}
	salt := pick(headerLabelSalt, c.Salt)
	key, err := hkdf.Key(v.hash, shared, salt, string(info), keyLen)
	if err != nil {
		return nil, fmt.Errorf("%w: HKDF: %w", ErrInvalidKey, err)
	}
	return key, nil
}

// kdfContext encodes COSE_KDF_Context (RFC 9053 §5.2):
// [AlgorithmID, [identity, nonce, other]U, [...]V, [keyDataLength, protected]].
func kdfContext(algID Algorithm, keyLen int, protected []byte, u, v PartyInfo) ([]byte, error) {
	if protected == nil {
		protected = []byte{}
	}
	party := func(p PartyInfo) corecbor.Value {
		b := func(x []byte) corecbor.Value {
			if x == nil {
				return corecbor.Null()
			}
			return corecbor.Bytes(x)
		}
		return corecbor.MakeArray(b(p.Identity), b(p.Nonce), b(p.Other))
	}
	return sharedEncoder.Encode(nil, corecbor.MakeArray(
		goToCBOR(int64(algID)),
		party(u),
		party(v),
		corecbor.MakeArray(corecbor.Uint(uint64(keyLen*8)), corecbor.Bytes(protected)),
	))
}

// ephemeralCOSEKey encodes an ephemeral public key as the COSE_Key the
// ephemeral-key header carries (RFC 9053 §6.3.1).
func ephemeralCOSEKey(pub *ecdh.PublicKey) (corecbor.Value, error) {
	var k *Key
	var err error
	if pub.Curve() == ecdh.X25519() {
		k, err = NewKeyFromPublic(pub)
	} else {
		var ec *ecdsa.PublicKey
		ec, err = ecdsa.ParseUncompressedPublicKey(ecdhToElliptic(pub.Curve()), pub.Bytes())
		if err == nil {
			k, err = NewKeyFromPublic(ec)
		}
	}
	if err != nil {
		return corecbor.Value{}, fmt.Errorf("%w: ephemeral key: %w", ErrInvalidKey, err)
	}
	return k.toValue()
}

// ephemeralFromHeaders decodes the ephemeral-key header as a COSE_Key
// and returns it as an ECDH public key on curve.
func ephemeralFromHeaders(h Headers, curve ecdh.Curve) (*ecdh.PublicKey, error) {
	raw, ok := h.params[headerLabelEphemeralKey]
	if !ok {
		return nil, fmt.Errorf("%w: missing ephemeral key in headers", ErrDecryption)
	}
	val, ok := raw.(corecbor.Value)
	if !ok {
		return nil, fmt.Errorf("%w: ephemeral key must be a COSE_Key", ErrMalformed)
	}
	k, err := keyFromValue(val, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %w", ErrMalformed, err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %w", ErrDecryption, err)
	}
	var out *ecdh.PublicKey
	switch p := pub.(type) {
	case *ecdh.PublicKey:
		out = p
	case *ecdsa.PublicKey:
		out, err = p.ECDH()
		if err != nil {
			return nil, fmt.Errorf("%w: ephemeral key: %w", ErrDecryption, err)
		}
	default:
		return nil, fmt.Errorf("%w: ephemeral key type %T", ErrDecryption, pub)
	}
	if out.Curve() != curve {
		return nil, fmt.Errorf("%w: ephemeral key is on a different curve", ErrDecryption)
	}
	return out, nil
}

func cekLenForAlg(alg Algorithm) int {
	switch alg {
	case AlgA128GCM, AlgAESCCM_16_64_128, AlgAESCCM_64_64_128, AlgAESCCM_16_128_128, AlgAESCCM_64_128_128:
		return 16
	case AlgA192GCM:
		return 24
	case AlgA256GCM, AlgAESCCM_16_64_256, AlgAESCCM_64_64_256, AlgAESCCM_16_128_256, AlgAESCCM_64_128_256:
		return 32
	default:
		return 0
	}
}

// --- v0.2 encoding (WithLegacyECDHES) ---

// DeriveKey performs ECDH + HKDF with the v0.2 context and returns the
// derived key and a raw-point ephemeral key header.
//
// Deprecated: v0.2's non-conformant ECDH-ES encoding (RFC 9053 §6.3);
// use ECDHESKey as an EncryptMulti recipient, or AgreeKey for direct key
// agreement. Removed no earlier than v0.32.0.
func (e *ECDHESKey) DeriveKey(opts KeyWrapOpts) (cek []byte, headers Headers, err error) {
	return e.legacyDerive(opts)
}

// UnderiveKey re-derives DeriveKey's key from the ephemeral key in h.
//
// Deprecated: see DeriveKey. Removed no earlier than v0.32.0.
func (e *ECDHESKey) UnderiveKey(h Headers, opts KeyUnwrapOpts) ([]byte, error) {
	raw, ok := h.Get(headerLabelEphemeralKey).([]byte)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("%w: missing ephemeral key in headers", ErrDecryption)
	}
	return e.legacyShared(raw, opts.CEKAlgorithm, opts.CEKLength)
}

func (e *ECDHESKey) legacyDerive(opts KeyWrapOpts) ([]byte, Headers, error) {
	if e.PeerPublic == nil {
		return nil, Headers{}, fmt.Errorf("%w: ECDHESKey.PeerPublic is nil", ErrInvalidKey)
	}
	ephemeral, err := e.PeerPublic.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: generating ephemeral key: %w", ErrInvalidKey, err)
	}
	shared, err := ephemeral.ECDH(e.PeerPublic)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: ECDH failed: %w", ErrInvalidKey, err)
	}
	derived, err := legacyHKDF(shared, opts.CEKAlgorithm, opts.CEKLength)
	if err != nil {
		return nil, Headers{}, err
	}
	return derived, Headers{params: map[any]any{headerLabelEphemeralKey: ephemeral.PublicKey().Bytes()}}, nil
}

func (e *ECDHESKey) legacyShared(raw []byte, contentAlg Algorithm, keyLen int) ([]byte, error) {
	if e.PrivateKey == nil {
		return nil, fmt.Errorf("%w: ECDHESKey.PrivateKey is nil", ErrInvalidKey)
	}
	peer, err := e.PrivateKey.Curve().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ephemeral key: %w", ErrDecryption, err)
	}
	shared, err := e.PrivateKey.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %w", ErrDecryption, err)
	}
	return legacyHKDF(shared, contentAlg, keyLen)
}

// legacyWrap is v0.2's -25: AES-KW under the derived key.
func (e *ECDHESKey) legacyWrap(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	derived, h, err := e.legacyDerive(opts)
	if err != nil {
		return nil, Headers{}, err
	}
	wrapped, err := aeskw.Wrap(derived, cek)
	if err != nil {
		return nil, Headers{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return wrapped, h, nil
}

func (e *ECDHESKey) legacyUnwrap(raw, ciphertext []byte, opts KeyUnwrapOpts) ([]byte, error) {
	derived, err := e.legacyShared(raw, opts.CEKAlgorithm, opts.CEKLength)
	if err != nil {
		return nil, err
	}
	cek, kerr := aeskw.Unwrap(derived, ciphertext)
	if kerr != nil {
		return nil, ErrDecryption
	}
	return cek, nil
}

// legacyHKDF is v0.2's HKDF-SHA-256 with its non-conformant context:
// [AlgID, partyU bstr, partyV bstr, [keyLength]], no salt.
func legacyHKDF(shared []byte, contentAlg Algorithm, keyLen int) ([]byte, error) {
	if keyLen == 0 {
		keyLen = cekLenForAlg(contentAlg)
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("%w: cannot determine CEK length", ErrInvalidKey)
	}
	info, err := sharedEncoder.Encode(nil, corecbor.MakeArray(
		goToCBOR(int64(contentAlg)),
		corecbor.Bytes(nil),
		corecbor.Bytes(nil),
		corecbor.MakeArray(goToCBOR(int64(keyLen*8))),
	))
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, string(info), keyLen)
	if err != nil {
		return nil, fmt.Errorf("%w: HKDF: %w", ErrInvalidKey, err)
	}
	return key, nil
}
