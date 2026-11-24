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
	"github.com/jahkeup/corecbor/internal/asreceived"
	"github.com/jahkeup/corecbor/internal/rawvalue"
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
	keep       bool
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

// KeepParamsAsReceived makes ParseKey, ParseKeyPrefix and ParseKeySet
// keep a parameter whose value is or contains a NaN or infinite float
// (ErrNonFiniteKeyParam), byte for byte, instead of rejecting the key.
// Such a parameter isn't interpreted: it is listed by ReceivedParams,
// can be removed with DeleteReceivedParam, and MarshalCBOR writes it
// verbatim, so for it the output is the input, not Core Deterministic.
// Labels -12 through 5, which the COSE key types define, are always
// parsed and checked.
func KeepParamsAsReceived() KeyOption {
	return func(c *keyParseConfig) { c.keep = true }
}

// ReceivedParams returns the parameters kept under KeepParamsAsReceived,
// keyed by label (an int64, or a string for a text label), with their
// encoded values as received. It returns a copy, or nil if there are
// none.
func (k *Key) ReceivedParams() map[any]corecbor.RawMessage {
	if len(k.received) == 0 {
		return nil
	}
	out := make(map[any]corecbor.RawMessage, len(k.received))
	for l, v := range k.received {
		out[l] = bytes.Clone(v)
	}
	return out
}

// DeleteReceivedParam removes a parameter kept under
// KeepParamsAsReceived. label is an int64 (or int), or a string.
func (k *Key) DeleteReceivedParam(label any) {
	if n, ok := label.(int); ok {
		label = int64(n)
	}
	delete(k.received, label)
}

func (k *Key) keepReceived(label any, raw []byte) {
	if k.received == nil {
		k.received = map[any]corecbor.RawMessage{}
	}
	k.received[label] = bytes.Clone(raw)
}

// definedLabel reports whether label is one the COSE key types define
// (RFC 9052 §7.1, RFC 9053 §7, RFC 8230, RFC 9864); those are never
// kept as received.
func definedLabel(label int64) bool { return label >= -12 && label <= 5 }

// newKeyDecoder is the decoder for COSE_Key and COSE_KeySet: duplicate
// labels are rejected (RFC 9052 §7), and so is text that isn't valid
// UTF-8 (RFC 8949 §3.1), so every parsed key can be re-encoded.
//
// Without the internal arena a Decoder keeps no per-call state, so one
// shared instance is safe for concurrent use.
func newKeyDecoder() *corecbor.Decoder { return keyDecoder }

var keyDecoder = corecbor.NewDecoder(corecbor.RejectDuplicateMapKeys(), corecbor.RejectInvalidUTF8(), corecbor.WithoutInternalArena())

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
	return keyFromValue(v, data, opts)
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
	k, err := keyFromValue(v, data[:len(data)-len(rest)], opts)
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
	for label, raw := range k.received {
		if !asreceived.OneItem(raw) {
			return corecbor.Value{}, &KeyParamError{Label: label, Err: fmt.Errorf("%w: received value is not one CBOR data item", ErrInvalidKey)}
		}
		lv := corecbor.Text("")
		switch l := label.(type) {
		case int64:
			lv = goToCBOR(l)
		case string:
			lv = corecbor.Text(l)
		}
		entries = append(entries, corecbor.MapEntry{Key: lv, Value: rawvalue.Make(raw)})
	}
	return corecbor.MakeMapFromSlice(entries), nil
}

// intLabel reads an integer COSE label without boxing it.
func intLabel(k corecbor.Value) (int64, error) {
	switch k.Kind {
	case corecbor.KindUint:
		if k.UintVal() <= math.MaxInt64 {
			return int64(k.UintVal()), nil
		}
	case corecbor.KindNegInt:
		if k.NegIntVal() <= math.MaxInt64 {
			return -1 - int64(k.NegIntVal()), nil
		}
	default:
		return 0, fmt.Errorf("%w: key label must be int or tstr", ErrMalformed)
	}
	return 0, fmt.Errorf("%w: key label out of range", ErrMalformed)
}

// keyFromValue builds a Key from a decoded COSE_Key. v must own its
// memory (decoded by newKeyDecoder: no arena, no zero-copy), because the
// Key keeps references to its byte strings and nested values.
// hasNonFinite reports whether v is or contains (in an array, map, or
// tag) a NaN or infinite float.
func hasNonFinite(v corecbor.Value) bool {
	switch v.Kind {
	case corecbor.KindFloat32:
		f := float64(v.Float32Val())
		return math.IsNaN(f) || math.IsInf(f, 0)
	case corecbor.KindFloat64:
		f := v.Float64Val()
		return math.IsNaN(f) || math.IsInf(f, 0)
	case corecbor.KindArray, corecbor.KindTag:
		for _, it := range v.Items {
			if hasNonFinite(it) {
				return true
			}
		}
	case corecbor.KindMap:
		for _, e := range v.Pairs {
			if hasNonFinite(e.Key) || hasNonFinite(e.Value) {
				return true
			}
		}
	}
	return false
}

func nonFiniteParamErr(label any) error {
	return &KeyParamError{Label: label, Err: fmt.Errorf("%w: %w", ErrMalformed, ErrNonFiniteKeyParam)}
}

// keyFromValue builds a Key from the decoded COSE_Key v. raw is v's
// source bytes, or nil; KeepParamsAsReceived needs it.
func keyFromValue(v corecbor.Value, raw []byte, opts []KeyOption) (*Key, error) {
	var cfg keyParseConfig
	if len(opts) > 0 {
		// Options take a pointer; building them on a separate value keeps
		// cfg on the stack for the common no-options call.
		c := new(keyParseConfig)
		for _, o := range opts {
			o(c)
		}
		cfg = *c
	}
	if v.Kind != corecbor.KindMap {
		return nil, fmt.Errorf("%w: COSE_Key must be a map", ErrMalformed)
	}
	var spans []asreceived.Span
	if cfg.keep && raw != nil {
		var err error
		if spans, err = asreceived.MapSpans(raw); err != nil || len(spans) != len(v.Pairs) {
			return nil, fmt.Errorf("%w: COSE_Key entries don't match their source", ErrMalformed)
		}
	}
	k := &Key{params: make(map[int64]any, len(v.Pairs))}
	for i, e := range v.Pairs {
		switch e.Key.Kind {
		case corecbor.KindText:
			if k.text == nil {
				k.text = map[string]corecbor.Value{}
			}
			if _, dup := k.text[e.Key.TextVal()]; dup {
				return nil, fmt.Errorf("%w: key label %q repeated", ErrMalformed, e.Key.TextVal())
			}
			if hasNonFinite(e.Value) {
				if spans == nil {
					return nil, nonFiniteParamErr(e.Key.TextVal())
				}
				k.keepReceived(e.Key.TextVal(), spans[i].Value)
				continue
			}
			k.text[e.Key.TextVal()] = e.Value
			continue
		}
		n, err := intLabel(e.Key)
		if err != nil {
			return nil, err
		}
		if _, dup := k.params[n]; dup {
			return nil, fmt.Errorf("%w: key label %d repeated", ErrMalformed, n)
		}
		if hasNonFinite(e.Value) {
			if spans == nil || definedLabel(n) {
				return nil, nonFiniteParamErr(n)
			}
			k.keepReceived(n, spans[i].Value)
			continue
		}
		k.params[n] = cborToGo(e.Value)
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
		// crypto/ecdh validates the point is on the curve (and not the
		// identity) without the big.Int affine conversion that
		// ecdsa.ParseUncompressedPublicKey does, so it allocates less.
		var buf [1 + 2*66]byte
		point := append(append(append(buf[:0], 0x04), x...), y...)
		ec, err := coseCurveToECDH(k.Curve())
		if err != nil {
			return err
		}
		if _, err := ec.NewPublicKey(point); err != nil {
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
	out := &Key{params: maps.Clone(k.params), text: maps.Clone(k.text), received: maps.Clone(k.received)}
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
// interface: alg direct gives a direct-encryption recipient whose key is
// the content key (RFC 9052 §8.5.1), A128KW/A192KW/A256KW an AESKWKey.
// Other key types and algorithms are ErrUnsupportedAlgorithm (ECDH-ES
// from EC2/OKP keys is proposal 029).
//
// For direct, the key's alg, when set, is direct or the content
// algorithm (for example A128GCM or HMAC 256/256), and the deriver then
// only works with that content algorithm; key_ops must permit the key's
// use as a content key: encrypt to seal and decrypt to open, or MAC
// create and MAC verify. For AES-KW, key_ops must permit wrapKey to wrap
// and unwrapKey to unwrap (RFC 9053 §6.2.1).
func (k *Key) KeyDeriver(alg Algorithm) (KeyDeriver, error) {
	if alg == AlgDirect {
		return k.directDeriver()
	}
	if !k.Permits(KeyOpWrapKey) && !k.Permits(KeyOpUnwrapKey) {
		return nil, fmt.Errorf("%w: key_ops permit neither wrapKey nor unwrapKey", ErrInvalidKey)
	}
	if a, ok := k.Algorithm(); ok && a != alg {
		return nil, fmt.Errorf("%w: key alg %s, requested %s", ErrAlgorithmMismatch, a, alg)
	}
	raw, err := k.SymmetricKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedAlgorithm, err)
	}
	switch alg {
	case AlgA128KW, AlgA192KW, AlgA256KW:
		kw := &AESKWKey{Key: raw}
		if kw.Algorithm() != alg {
			return nil, fmt.Errorf("%w: %d-byte key for %s", ErrInvalidKey, len(raw), alg)
		}
		if k.get(keyLabelKeyOps) == nil {
			return kw, nil
		}
		return &keyAESKW{AESKWKey: *kw, key: k}, nil
	default:
		return nil, fmt.Errorf("%w: %s from a symmetric key", ErrUnsupportedAlgorithm, alg)
	}
}

// keyAESKW is an AES-KW recipient made from a COSE_Key with key_ops: it
// wraps only if they permit wrapKey and unwraps only if they permit
// unwrapKey (RFC 9053 §6.2.1).
type keyAESKW struct {
	AESKWKey
	key *Key
}

func (a *keyAESKW) WrapKey(cek []byte, opts KeyWrapOpts) ([]byte, Headers, error) {
	if !a.key.Permits(KeyOpWrapKey) {
		return nil, Headers{}, fmt.Errorf("%w: key_ops do not permit wrapKey", ErrInvalidKey)
	}
	return a.AESKWKey.WrapKey(cek, opts)
}

func (a *keyAESKW) UnwrapKey(ct []byte, h Headers, opts KeyUnwrapOpts) ([]byte, error) {
	if !a.key.Permits(KeyOpUnwrapKey) {
		return nil, fmt.Errorf("%w: key_ops do not permit unwrapKey", ErrInvalidKey)
	}
	return a.AESKWKey.UnwrapKey(ct, h, opts)
}

func (k *Key) directDeriver() (KeyDeriver, error) {
	if !k.Permits(KeyOpEncrypt) && !k.Permits(KeyOpDecrypt) && !k.Permits(KeyOpMACCreate) && !k.Permits(KeyOpMACVerify) {
		return nil, fmt.Errorf("%w: key_ops don't permit use as a content key (encrypt, decrypt, MAC create or MAC verify)", ErrInvalidKey)
	}
	d := &keyDirect{key: k}
	if a, ok := k.Algorithm(); ok && a != AlgDirect {
		if !isContentAlg(a) {
			return nil, fmt.Errorf("%w: key alg %s, requested direct", ErrAlgorithmMismatch, a)
		}
		d.contentAlg = a
	}
	raw, err := k.SymmetricKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedAlgorithm, err)
	}
	d.DirectKey = DirectKey{Key: raw}
	return d, nil
}

// isContentAlg reports whether a is a content-layer algorithm a direct
// key can be restricted to: AEAD content encryption or HMAC.
func isContentAlg(a Algorithm) bool {
	if cekLenForAlg(a) > 0 {
		return true
	}
	_, err := hmacHashFunc(a)
	return err == nil
}

// keyDirect is a direct-encryption recipient made from a COSE_Key. It
// enforces the key's alg (as the content algorithm) and its key_ops.
type keyDirect struct {
	DirectKey
	key        *Key
	contentAlg Algorithm // 0: any
}

func (d *keyDirect) UnwrapKey(ct []byte, h Headers, opts KeyUnwrapOpts) ([]byte, error) {
	if d.contentAlg != 0 && opts.CEKAlgorithm != d.contentAlg {
		return nil, fmt.Errorf("%w: key alg %s, content alg %s", ErrAlgorithmMismatch, d.contentAlg, opts.CEKAlgorithm)
	}
	_, notMAC := hmacHashFunc(opts.CEKAlgorithm)
	var op KeyOp
	var name string
	switch {
	case opts.seal && notMAC == nil:
		op, name = KeyOpMACCreate, "MAC create"
	case opts.seal:
		op, name = KeyOpEncrypt, "encrypt"
	case notMAC == nil:
		op, name = KeyOpMACVerify, "MAC verify"
	default:
		op, name = KeyOpDecrypt, "decrypt"
	}
	if !d.key.Permits(op) {
		return nil, fmt.Errorf("%w: key_ops do not permit %s", ErrInvalidKey, name)
	}
	return d.DirectKey.UnwrapKey(ct, h, opts)
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
	var raws [][]byte
	if len(opts) > 0 {
		if raws, err = asreceived.ArraySpans(data); err != nil || len(raws) != len(v.Items) {
			return nil, fmt.Errorf("%w: COSE_KeySet items don't match their source", ErrMalformed)
		}
	}
	ks := make(KeySet, len(v.Items))
	for i, it := range v.Items {
		var raw []byte
		if raws != nil {
			raw = raws[i]
		}
		k, err := keyFromValue(it, raw, opts)
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
//
// alg matches exactly: a key whose alg is ES256 (-7) doesn't match
// ESP256 (-9), nor EdDSA (-8) Ed25519 (-19). A key's alg restricts it to
// that algorithm (RFC 9052 §7.1), and RFC 9864 gives the polymorphic
// and fully-specified identifiers distinct meanings, so such a key
// couldn't verify the message anyway (NewVerifierFromKey). A key meant
// for both forms leaves alg unset.
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
