// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"maps"
	"math"
	"math/big"
	"slices"

	"github.com/jahkeup/corecbor"
)

// Key type parameter labels (RFC 9053 §7, RFC 8230 §4, RFC 9964 §3).
// Negative labels are interpreted per kty.
const (
	keyLabelKeyOps int64 = 4
	keyLabelBaseIV int64 = 5

	keyLabelRSAN int64 = -1 // modulus
	keyLabelRSAE int64 = -2 // public exponent
	keyLabelRSAD int64 = -3 // private exponent; -4..-12 are further private members

	keyLabelSymK int64 = -1

	keyLabelAKPPub  int64 = -1
	keyLabelAKPPriv int64 = -2
)

// KeyOp is a COSE_Key key_ops value (RFC 9052 §7.1, Table 5).
type KeyOp int

const (
	KeyOpSign KeyOp = 1 + iota
	KeyOpVerify
	KeyOpEncrypt
	KeyOpDecrypt
	KeyOpWrapKey
	KeyOpUnwrapKey
	KeyOpDeriveKey
	KeyOpDeriveBits
	KeyOpMACCreate
	KeyOpMACVerify
)

// keyParseConfig holds KeyOption settings.
type keyParseConfig struct {
	allowShort bool
}

// KeyOption adjusts COSE_Key parsing.
type KeyOption func(*keyParseConfig)

// AllowShortCoordinates makes ParseKey and ParseKeyPrefix left-pad EC2
// coordinates (and an EC2 d) shorter than the curve size instead of
// rejecting them, for peers that strip leading zeros. RFC 9053 §7.1.1
// requires leading zeros to be preserved, so the parsers reject short
// coordinates by default. (*Key).PublicKey keeps left-padding, as in
// v0.2.2.
func AllowShortCoordinates() KeyOption {
	return func(c *keyParseConfig) { c.allowShort = true }
}

// newKeyDecoder is the decoder for COSE_Key and COSE_KeySet: duplicate
// labels are rejected (RFC 9052 §7), and so is text that isn't valid
// UTF-8 (RFC 8949 §3.1), so every parsed key can be re-encoded.
func newKeyDecoder() *corecbor.Decoder {
	return corecbor.NewDecoder(corecbor.RejectDuplicateMapKeys(), corecbor.RejectInvalidUTF8())
}

// ParseKey decodes one COSE_Key (RFC 9052 §7). data must hold exactly
// one item. Duplicate labels are ErrMalformed; a missing or unsupported
// kty, missing or mis-sized key material, an off-curve point, or a
// private key that doesn't match its public part is ErrInvalidKey.
// A compressed EC2 point (y as a bool) is decompressed, so the parsed
// key always has a bstr y.
func ParseKey(data []byte, opts ...KeyOption) (*Key, error) {
	v, err := newKeyDecoder().Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}
	return keyFromValue(v, opts)
}

// ParseKeyPrefix decodes one COSE_Key from the front of data and
// returns the bytes after it, for formats that append data to a key
// (for example WebAuthn attested credential data followed by
// extensions).
func ParseKeyPrefix(data []byte, opts ...KeyOption) (*Key, []byte, error) {
	v, rest, err := newKeyDecoder().DecodePrefix(data)
	if err != nil {
		return nil, nil, decodeError(err)
	}
	k, err := keyFromValue(v, opts)
	if err != nil {
		return nil, nil, err
	}
	return k, rest, nil
}

// UnmarshalCBOR decodes a COSE_Key into k, as ParseKey does with no
// options.
func (k *Key) UnmarshalCBOR(data []byte) error {
	nk, err := ParseKey(data)
	if err != nil {
		return err
	}
	*k = *nk
	return nil
}

// MarshalCBOR encodes k as a COSE_Key in Core Deterministic encoding.
func (k *Key) MarshalCBOR() ([]byte, error) {
	v, err := k.toValue()
	if err != nil {
		return nil, err
	}
	return sharedEncoder.Encode(nil, v)
}

func (k *Key) toValue() (corecbor.Value, error) {
	entries := make([]corecbor.MapEntry, 0, len(k.params)+len(k.text))
	for label, v := range k.params {
		cv, err := goToCBORChecked(v)
		if err != nil {
			return corecbor.Value{}, fmt.Errorf("%w: key label %d: %w", ErrInvalidKey, label, err)
		}
		entries = append(entries, corecbor.MapEntry{Key: goToCBOR(label), Value: cv})
	}
	for label, v := range k.text {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Text(label), Value: v})
	}
	return corecbor.MakeMapFromSlice(entries), nil
}

func keyFromValue(v corecbor.Value, opts []KeyOption) (*Key, error) {
	var cfg keyParseConfig
	for _, o := range opts {
		o(&cfg)
	}
	if v.Kind != corecbor.KindMap {
		return nil, fmt.Errorf("%w: COSE_Key must be a map", ErrMalformed)
	}
	k := &Key{params: make(map[int64]any, len(v.Pairs))}
	for _, e := range v.Pairs {
		switch e.Key.Kind {
		case corecbor.KindText:
			if k.text == nil {
				k.text = map[string]corecbor.Value{}
			}
			if _, dup := k.text[e.Key.TextVal()]; dup {
				return nil, fmt.Errorf("%w: key label %q repeated", ErrMalformed, e.Key.TextVal())
			}
			k.text[e.Key.TextVal()] = e.Value.Clone()
			continue
		}
		label, err := labelToGo(e.Key)
		if err != nil {
			return nil, err
		}
		n := label.(int64)
		if _, dup := k.params[n]; dup {
			return nil, fmt.Errorf("%w: key label %d repeated", ErrMalformed, n)
		}
		k.params[n] = cborToGo(e.Value.Clone())
	}
	if err := k.validate(cfg); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *Key) bytesParam(label int64) ([]byte, bool) {
	b, ok := k.get(label).([]byte)
	return b, ok
}

// validate checks the common parameters and the material for kty, and
// normalizes EC2 points (padding under cfg.allowShort, decompression).
func (k *Key) validate(cfg keyParseConfig) error {
	ktyV, ok := k.get(keyLabelKty).(int64)
	if !ok {
		return fmt.Errorf("%w: COSE_Key needs an integer kty", ErrInvalidKey)
	}
	if v := k.get(keyLabelKid); v != nil {
		if _, ok := v.([]byte); !ok {
			return fmt.Errorf("%w: kid must be a bstr", ErrInvalidKey)
		}
	}
	if v := k.get(keyLabelAlg); v != nil {
		if _, err := algValue(v); err != nil {
			return fmt.Errorf("%w: alg must be an integer", ErrInvalidKey)
		}
	}
	if v := k.get(keyLabelKeyOps); v != nil {
		ops, ok := v.(corecbor.Value)
		if !ok || ops.Kind != corecbor.KindArray || len(ops.Items) == 0 {
			return fmt.Errorf("%w: key_ops must be a non-empty array", ErrInvalidKey)
		}
	}
	if v := k.get(keyLabelBaseIV); v != nil {
		if _, ok := v.([]byte); !ok {
			return fmt.Errorf("%w: Base IV must be a bstr", ErrInvalidKey)
		}
	}
	switch KeyType(ktyV) {
	case KeyTypeOKP:
		return k.validateOKP()
	case KeyTypeEC2:
		return k.validateEC2(cfg)
	case KeyTypeRSA:
		return k.validateRSA()
	case KeyTypeSymmetric:
		if b, ok := k.bytesParam(keyLabelSymK); !ok || len(b) == 0 {
			return fmt.Errorf("%w: symmetric key needs a non-empty k", ErrInvalidKey)
		}
		return nil
	case KeyTypeAKP:
		if _, ok := k.Algorithm(); !ok {
			return fmt.Errorf("%w: AKP key needs alg (RFC 9964 §3)", ErrInvalidKey)
		}
		_, hasPub := k.bytesParam(keyLabelAKPPub)
		_, hasPriv := k.bytesParam(keyLabelAKPPriv)
		if !hasPub && !hasPriv {
			return fmt.Errorf("%w: AKP key needs pub or priv", ErrInvalidKey)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported kty %d", ErrInvalidKey, ktyV)
	}
}

// okpSize returns the x (and d) length for an OKP curve.
func okpSize(crv Curve) (int, bool) {
	switch crv {
	case CurveX25519, CurveEd25519:
		return 32, true
	case CurveX448:
		return 56, true
	case CurveEd448:
		return 57, true
	default:
		return 0, false
	}
}

func (k *Key) validateOKP() error {
	size, ok := okpSize(k.Curve())
	if !ok {
		return fmt.Errorf("%w: unsupported OKP curve %d", ErrInvalidKey, k.Curve())
	}
	x, hasX := k.bytesParam(keyLabelX)
	d, hasD := k.bytesParam(keyLabelD)
	if !hasX && !hasD {
		return fmt.Errorf("%w: OKP key needs x or d", ErrInvalidKey)
	}
	if hasX && len(x) != size {
		return fmt.Errorf("%w: OKP x is %d bytes, want %d", ErrInvalidKey, len(x), size)
	}
	if hasD && len(d) != size {
		return fmt.Errorf("%w: OKP d is %d bytes, want %d", ErrInvalidKey, len(d), size)
	}
	if hasX && hasD {
		if pub, ok := okpPublicFromPrivate(k.Curve(), d); ok && !bytes.Equal(pub, x) {
			return fmt.Errorf("%w: OKP d does not match x", ErrInvalidKey)
		}
	}
	return nil
}

// okpPublicFromPrivate derives x from d where the standard library can.
func okpPublicFromPrivate(crv Curve, d []byte) ([]byte, bool) {
	switch crv {
	case CurveEd25519:
		return ed25519PublicFromSeed(d), true
	case CurveX25519:
		priv, err := ecdh.X25519().NewPrivateKey(d)
		if err != nil {
			return nil, false
		}
		return priv.PublicKey().Bytes(), true
	default:
		return nil, false
	}
}

func (k *Key) validateEC2(cfg keyParseConfig) error {
	goCrv, err := coseCurveToGo(k.Curve())
	if err != nil {
		return err
	}
	size := curveKeySize(goCrv)
	fix := func(label int64, name string) ([]byte, bool, error) {
		b, ok := k.bytesParam(label)
		if !ok {
			return nil, false, nil
		}
		switch {
		case len(b) == size:
			return b, true, nil
		case len(b) < size && cfg.allowShort:
			p := padLeft(b, size)
			k.params[label] = p
			return p, true, nil
		default:
			return nil, false, fmt.Errorf("%w: EC2 %s is %d bytes, want %d", ErrInvalidKey, name, len(b), size)
		}
	}
	x, hasX, err := fix(keyLabelX, "x")
	if err != nil {
		return err
	}
	d, hasD, err := fix(keyLabelD, "d")
	if err != nil {
		return err
	}
	if !hasX && !hasD {
		return fmt.Errorf("%w: EC2 key needs x and y, or d", ErrInvalidKey)
	}
	var y []byte
	switch yv := k.get(keyLabelY).(type) {
	case nil:
		if hasX {
			return fmt.Errorf("%w: EC2 key with x needs y", ErrInvalidKey)
		}
	case bool:
		if !hasX {
			return fmt.Errorf("%w: compressed EC2 y needs x", ErrInvalidKey)
		}
		y, err = decompressY(goCrv, x, yv)
		if err != nil {
			return err
		}
		k.params[keyLabelY] = y
	default:
		y, _, err = fix(keyLabelY, "y")
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("%w: EC2 y must be a bstr or bool", ErrInvalidKey)
		}
	}
	if hasX {
		point := append(append([]byte{0x04}, x...), y...)
		if _, err := ecdsa.ParseUncompressedPublicKey(goCrv, point); err != nil {
			return fmt.Errorf("%w: EC2 point: %w", ErrInvalidKey, err)
		}
	}
	if hasD {
		priv, err := ecdsa.ParseRawPrivateKey(goCrv, d)
		if err != nil {
			return fmt.Errorf("%w: EC2 d: %w", ErrInvalidKey, err)
		}
		if hasX {
			raw, err := priv.PublicKey.Bytes()
			if err != nil || !bytes.Equal(raw[1:1+size], x) || !bytes.Equal(raw[1+size:], y) {
				return fmt.Errorf("%w: EC2 d does not match x, y", ErrInvalidKey)
			}
		}
	}
	return nil
}

// decompressY recovers y from x and the SEC1 sign bit (RFC 9053 §7.1.1:
// false is even, true is odd). P-256, P-384 and P-521 have p ≡ 3 mod 4,
// so the square root is a^((p+1)/4).
func decompressY(curve elliptic.Curve, x []byte, odd bool) ([]byte, error) {
	params := curve.Params()
	p := params.P
	xi := new(big.Int).SetBytes(x)
	if xi.Cmp(p) >= 0 {
		return nil, fmt.Errorf("%w: EC2 x out of range", ErrInvalidKey)
	}
	// y² = x³ - 3x + b
	y2 := new(big.Int).Exp(xi, big.NewInt(3), p)
	y2.Sub(y2, new(big.Int).Mul(big.NewInt(3), xi))
	y2.Add(y2, params.B)
	y2.Mod(y2, p)
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, p)
	if new(big.Int).Exp(y, big.NewInt(2), p).Cmp(y2) != 0 {
		return nil, fmt.Errorf("%w: EC2 x is not on the curve", ErrInvalidKey)
	}
	if (y.Bit(0) == 1) != odd {
		y.Sub(p, y)
	}
	out := make([]byte, curveKeySize(curve))
	return y.FillBytes(out), nil
}

func (k *Key) validateRSA() error {
	n, hasN := k.bytesParam(keyLabelRSAN)
	e, hasE := k.bytesParam(keyLabelRSAE)
	if !hasN || !hasE || len(e) == 0 {
		return fmt.Errorf("%w: RSA key needs n and e", ErrInvalidKey)
	}
	if bits := new(big.Int).SetBytes(n).BitLen(); bits < minRSABits {
		return fmt.Errorf("%w: RSA modulus is %d bits, want at least %d", ErrInvalidKey, bits, minRSABits)
	}
	if len(e) > 8 || new(big.Int).SetBytes(e).Cmp(big.NewInt(math.MaxInt32)) > 0 {
		return fmt.Errorf("%w: RSA public exponent too large", ErrInvalidKey)
	}
	return nil
}

// ID returns the key's kid (label 2), or nil.
func (k *Key) ID() []byte {
	b, _ := k.bytesParam(keyLabelKid)
	return b
}

// SetID sets the key's kid (label 2).
func (k *Key) SetID(kid []byte) { k.set(keyLabelKid, kid) }

// Algorithm returns the key's alg (label 3) and whether it is set.
func (k *Key) Algorithm() (Algorithm, bool) {
	v := k.get(keyLabelAlg)
	if v == nil {
		return 0, false
	}
	a, err := algValue(v)
	return a, err == nil
}

// SetAlgorithm sets the key's alg (label 3).
func (k *Key) SetAlgorithm(alg Algorithm) { k.set(keyLabelAlg, int64(alg)) }

// Ops returns the integer key_ops (label 4). Text-valued operations are
// not representable as KeyOp and are omitted.
func (k *Key) Ops() []KeyOp {
	v, ok := k.get(keyLabelKeyOps).(corecbor.Value)
	if !ok || v.Kind != corecbor.KindArray {
		return nil
	}
	var out []KeyOp
	for _, it := range v.Items {
		if it.Kind == corecbor.KindUint && it.UintVal() <= math.MaxInt32 {
			out = append(out, KeyOp(it.UintVal()))
		}
	}
	return out
}

// SetOps sets key_ops (label 4).
func (k *Key) SetOps(ops ...KeyOp) {
	items := make([]corecbor.Value, len(ops))
	for i, op := range ops {
		items[i] = corecbor.Uint(uint64(op))
	}
	k.set(keyLabelKeyOps, corecbor.MakeArrayFromSlice(items))
}

// Permits reports whether key_ops allows op. A key without key_ops
// permits every operation (RFC 9052 §7.1).
func (k *Key) Permits(op KeyOp) bool {
	if k.get(keyLabelKeyOps) == nil {
		return true
	}
	return slices.Contains(k.Ops(), op)
}

// BaseIV returns the Base IV (label 5), or nil.
func (k *Key) BaseIV() []byte {
	b, _ := k.bytesParam(keyLabelBaseIV)
	return b
}

// privateLabels lists the private parameters for kty.
func privateLabels(kty KeyType) []int64 {
	switch kty {
	case KeyTypeOKP, KeyTypeEC2:
		return []int64{keyLabelD}
	case KeyTypeRSA:
		return []int64{keyLabelRSAD, -4, -5, -6, -7, -8, -9, -10, -11, -12}
	case KeyTypeAKP:
		return []int64{keyLabelAKPPriv}
	default:
		return nil
	}
}

// Public returns a copy of k without private parameters. A symmetric key
// has no public part and is ErrInvalidKey; so is a private key whose
// public parameters are absent.
func (k *Key) Public() (*Key, error) {
	kty := k.KeyType()
	if kty == KeyTypeSymmetric {
		return nil, fmt.Errorf("%w: a symmetric key has no public part", ErrInvalidKey)
	}
	out := &Key{params: maps.Clone(k.params), text: maps.Clone(k.text)}
	for _, l := range privateLabels(kty) {
		delete(out.params, l)
	}
	switch kty {
	case KeyTypeOKP, KeyTypeEC2:
		if out.get(keyLabelX) == nil {
			return nil, fmt.Errorf("%w: key has no public coordinates", ErrInvalidKey)
		}
	case KeyTypeAKP:
		if out.get(keyLabelAKPPub) == nil {
			return nil, fmt.Errorf("%w: AKP key has no pub", ErrInvalidKey)
		}
	}
	return out, nil
}

// thumbprintLabels lists the required parameters of RFC 9679 §4 (and
// RFC 9964 §6 for AKP), in addition to kty.
func thumbprintLabels(kty KeyType) ([]int64, error) {
	switch kty {
	case KeyTypeOKP:
		return []int64{keyLabelCrv, keyLabelX}, nil
	case KeyTypeEC2:
		return []int64{keyLabelCrv, keyLabelX, keyLabelY}, nil
	case KeyTypeRSA:
		return []int64{keyLabelRSAN, keyLabelRSAE}, nil
	case KeyTypeSymmetric:
		return []int64{keyLabelSymK}, nil
	case KeyTypeAKP:
		return []int64{keyLabelAlg, keyLabelAKPPub}, nil
	default:
		return nil, fmt.Errorf("%w: no thumbprint definition for kty %d", ErrInvalidKey, kty)
	}
}

// Thumbprint returns the COSE Key Thumbprint (RFC 9679): the hash h of
// the deterministic encoding of kty and the key type's required
// parameters. SHA-256 is the mandatory-to-implement hash.
func (k *Key) Thumbprint(h crypto.Hash) ([]byte, error) {
	if !h.Available() {
		return nil, fmt.Errorf("%w: hash %v not available", ErrUnsupportedAlgorithm, h)
	}
	kty := k.KeyType()
	labels, err := thumbprintLabels(kty)
	if err != nil {
		return nil, err
	}
	entries := []corecbor.MapEntry{{Key: goToCBOR(keyLabelKty), Value: goToCBOR(int64(kty))}}
	for _, l := range labels {
		v := k.get(l)
		if v == nil {
			return nil, fmt.Errorf("%w: thumbprint needs key label %d", ErrInvalidKey, l)
		}
		cv, err := goToCBORChecked(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		entries = append(entries, corecbor.MapEntry{Key: goToCBOR(l), Value: cv})
	}
	enc, err := sharedEncoder.Encode(nil, corecbor.MakeMapFromSlice(entries))
	if err != nil {
		return nil, err
	}
	hh := h.New()
	hh.Write(enc)
	return hh.Sum(nil), nil
}

// SymmetricKey returns the k parameter of a symmetric (kty 4) key.
func (k *Key) SymmetricKey() ([]byte, error) {
	if k.KeyType() != KeyTypeSymmetric {
		return nil, fmt.Errorf("%w: kty %d is not symmetric", ErrInvalidKey, k.KeyType())
	}
	b, ok := k.bytesParam(keyLabelSymK)
	if !ok || len(b) == 0 {
		return nil, fmt.Errorf("%w: symmetric key has no k", ErrInvalidKey)
	}
	return b, nil
}

// KeyDeriver adapts a symmetric key to the encryption KeyDeriver
// interface: alg direct gives a DirectKey, A128KW/A192KW/A256KW an
// AESKWKey. Other key types and algorithms are ErrUnsupportedAlgorithm
// (ECDH-ES from EC2/OKP keys is proposal 029).
func (k *Key) KeyDeriver(alg Algorithm) (KeyDeriver, error) {
	if !k.Permits(KeyOpWrapKey) && !k.Permits(KeyOpUnwrapKey) && !k.Permits(KeyOpEncrypt) && !k.Permits(KeyOpDecrypt) {
		return nil, fmt.Errorf("%w: key_ops forbid key distribution", ErrInvalidKey)
	}
	if a, ok := k.Algorithm(); ok && a != alg {
		return nil, fmt.Errorf("%w: key alg %s, requested %s", ErrAlgorithmMismatch, a, alg)
	}
	raw, err := k.SymmetricKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedAlgorithm, err)
	}
	switch alg {
	case AlgDirect:
		return &DirectKey{Key: raw}, nil
	case AlgA128KW, AlgA192KW, AlgA256KW:
		kw := &AESKWKey{Key: raw}
		if kw.Algorithm() != alg {
			return nil, fmt.Errorf("%w: %d-byte key for %s", ErrInvalidKey, len(raw), alg)
		}
		return kw, nil
	default:
		return nil, fmt.Errorf("%w: %s from a symmetric key", ErrUnsupportedAlgorithm, alg)
	}
}

// KeySet is a COSE_KeySet (RFC 9052 §7): an array of COSE_Key.
type KeySet []*Key

// ParseKeySet decodes a COSE_KeySet. Every key is parsed as ParseKey
// does with opts.
func ParseKeySet(data []byte, opts ...KeyOption) (KeySet, error) {
	v, err := newKeyDecoder().Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}
	if v.Kind != corecbor.KindArray || len(v.Items) == 0 {
		return nil, fmt.Errorf("%w: COSE_KeySet must be a non-empty array", ErrMalformed)
	}
	ks := make(KeySet, len(v.Items))
	for i, it := range v.Items {
		k, err := keyFromValue(it, opts)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		ks[i] = k
	}
	return ks, nil
}

// MarshalCBOR encodes ks as a COSE_KeySet.
func (ks KeySet) MarshalCBOR() ([]byte, error) {
	items := make([]corecbor.Value, len(ks))
	for i, k := range ks {
		v, err := k.toValue()
		if err != nil {
			return nil, err
		}
		items[i] = v
	}
	return sharedEncoder.Encode(nil, corecbor.MakeArrayFromSlice(items))
}

// Lookup returns the keys whose kid equals kid (when kid is non-nil),
// whose alg equals alg or is unset (when alg is non-zero), and whose
// key_ops permit op (when op is non-zero), in set order.
func (ks KeySet) Lookup(kid []byte, alg Algorithm, op KeyOp) []*Key {
	var out []*Key
	for _, k := range ks {
		if kid != nil && !bytes.Equal(k.ID(), kid) {
			continue
		}
		if alg != 0 {
			if a, ok := k.Algorithm(); ok && a != alg {
				continue
			}
		}
		if op != 0 && !k.Permits(op) {
			continue
		}
		out = append(out, k)
	}
	return out
}
