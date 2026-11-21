// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"unicode/utf8"

	"github.com/jahkeup/corecbor"
)

// JWK interop (RFC 7517, RFC 7518 §6, RFC 8037, RFC 9964 for AKP).

var jwkKty = map[string]KeyType{"OKP": KeyTypeOKP, "EC": KeyTypeEC2, "RSA": KeyTypeRSA, "oct": KeyTypeSymmetric, "AKP": KeyTypeAKP}

var jwkCrv = map[string]Curve{
	"P-256": CurveP256, "P-384": CurveP384, "P-521": CurveP521,
	"X25519": CurveX25519, "X448": CurveX448, "Ed25519": CurveEd25519, "Ed448": CurveEd448,
}

// jwkAlg maps JOSE algorithm names to COSE identifiers (IANA JOSE and
// COSE registries; fully-specified names per RFC 9864).
var jwkAlg = map[string]Algorithm{
	"ES256": AlgES256, "ES384": AlgES384, "ES512": AlgES512, "EdDSA": AlgEdDSA,
	"Ed25519": -19, "ESP256": -9, "ESP384": -51, "ESP512": -52,
	"PS256": AlgPS256, "PS384": AlgPS384, "PS512": AlgPS512,
	"RS256": AlgRS256, "RS384": AlgRS384, "RS512": AlgRS512,
	"HS256": AlgHMAC256, "HS384": AlgHMAC384, "HS512": AlgHMAC512,
	"A128KW": AlgA128KW, "A192KW": AlgA192KW, "A256KW": AlgA256KW,
	"A128GCM": AlgA128GCM, "A192GCM": AlgA192GCM, "A256GCM": AlgA256GCM,
	"dir":       AlgDirect,
	"ML-DSA-44": -48, "ML-DSA-65": -49, "ML-DSA-87": -50,
}

// jwkMembers lists, per kty, the base64url members and their COSE labels.
var jwkMembers = map[KeyType][]struct {
	name  string
	label int64
}{
	KeyTypeOKP:       {{"x", keyLabelX}, {"d", keyLabelD}},
	KeyTypeEC2:       {{"x", keyLabelX}, {"y", keyLabelY}, {"d", keyLabelD}},
	KeyTypeRSA:       {{"n", -1}, {"e", -2}, {"d", -3}, {"p", -4}, {"q", -5}, {"dp", -6}, {"dq", -7}, {"qi", -8}},
	KeyTypeSymmetric: {{"k", keyLabelSymK}},
	KeyTypeAKP:       {{"pub", keyLabelAKPPub}, {"priv", keyLabelAKPPriv}},
}

var jwkOps = map[string]KeyOp{
	"sign": KeyOpSign, "verify": KeyOpVerify, "encrypt": KeyOpEncrypt, "decrypt": KeyOpDecrypt,
	"wrapKey": KeyOpWrapKey, "unwrapKey": KeyOpUnwrapKey, "deriveKey": KeyOpDeriveKey, "deriveBits": KeyOpDeriveBits,
}

var b64 = base64.RawURLEncoding

// KeyFromJWK converts a JWK to a COSE_Key, validated as ParseKey does
// (EC coordinates must be full length, RFC 7518 §6.2.1.2). kid becomes
// the UTF-8 bytes of the string. "use" is converted to the equivalent
// key_ops so a usage restriction isn't lost ("sig": sign, verify; "enc":
// encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits). For oct
// keys, "sign" and "verify" key_ops mean MAC create and MAC verify. An
// unknown kty, crv or alg is ErrInvalidKey / ErrUnsupportedAlgorithm.
// Members with no COSE equivalent (x5c, x5t, …) are dropped.
func KeyFromJWK(jwk []byte) (*Key, error) {
	var m map[string]any
	if err := json.Unmarshal(jwk, &m); err != nil {
		return nil, fmt.Errorf("%w: JWK: %w", ErrMalformed, err)
	}
	str := func(name string) (string, bool, error) {
		v, ok := m[name]
		if !ok {
			return "", false, nil
		}
		s, ok := v.(string)
		if !ok {
			return "", false, fmt.Errorf("%w: JWK %q must be a string", ErrMalformed, name)
		}
		return s, true, nil
	}
	ktyName, ok, err := str("kty")
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: JWK needs a kty string", ErrInvalidKey)
	}
	kty, ok := jwkKty[ktyName]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported JWK kty %q", ErrInvalidKey, ktyName)
	}
	k := &Key{params: map[int64]any{keyLabelKty: int64(kty)}}
	if crv, ok, err := str("crv"); err != nil {
		return nil, err
	} else if ok {
		c, known := jwkCrv[crv]
		if !known {
			return nil, fmt.Errorf("%w: unsupported JWK crv %q", ErrInvalidKey, crv)
		}
		k.params[keyLabelCrv] = int64(c)
	}
	for _, mem := range jwkMembers[kty] {
		s, ok, err := str(mem.name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		b, err := b64.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%w: JWK %q: %w", ErrMalformed, mem.name, err)
		}
		k.params[mem.label] = b
	}
	if kid, ok, err := str("kid"); err != nil {
		return nil, err
	} else if ok {
		k.params[keyLabelKid] = []byte(kid)
	}
	if alg, ok, err := str("alg"); err != nil {
		return nil, err
	} else if ok {
		a, known := jwkAlg[alg]
		if !known {
			return nil, fmt.Errorf("%w: JWK alg %q", ErrUnsupportedAlgorithm, alg)
		}
		k.params[keyLabelAlg] = int64(a)
	}
	ops, err := jwkKeyOps(m, kty)
	if err != nil {
		return nil, err
	}
	if ops != nil {
		k.SetOps(ops...)
	}
	if err := k.validate(keyParseConfig{}); err != nil {
		return nil, err
	}
	return k, nil
}

func jwkKeyOps(m map[string]any, kty KeyType) ([]KeyOp, error) {
	var names []string
	if v, ok := m["key_ops"]; ok {
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			return nil, fmt.Errorf("%w: JWK key_ops must be a non-empty array", ErrMalformed)
		}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("%w: JWK key_ops entries must be strings", ErrMalformed)
			}
			names = append(names, s)
		}
	} else if use, ok := m["use"].(string); ok {
		switch use {
		case "sig":
			names = []string{"sign", "verify"}
		case "enc":
			names = []string{"encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"}
		default:
			return nil, fmt.Errorf("%w: JWK use %q", ErrInvalidKey, use)
		}
	}
	if names == nil {
		return nil, nil
	}
	ops := make([]KeyOp, 0, len(names))
	for _, n := range names {
		op, ok := jwkOps[n]
		if !ok {
			return nil, fmt.Errorf("%w: JWK key_ops %q", ErrInvalidKey, n)
		}
		if kty == KeyTypeSymmetric {
			switch op {
			case KeyOpSign:
				op = KeyOpMACCreate
			case KeyOpVerify:
				op = KeyOpMACVerify
			}
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// JWK converts k to a JWK (JSON). Private members are included only if
// present; use Public first to drop them. A kid that isn't valid UTF-8
// is written base64url-encoded. Integer key_ops become JWK names (MAC
// create/verify as "sign"/"verify"). A parameter with no JWK equivalent
// is ErrUnsupportedAlgorithm.
func (k *Key) JWK() ([]byte, error) {
	kty := k.KeyType()
	var ktyName string
	for n, t := range jwkKty {
		if t == kty {
			ktyName = n
		}
	}
	if ktyName == "" {
		return nil, fmt.Errorf("%w: no JWK kty for %d", ErrInvalidKey, kty)
	}
	out := map[string]any{"kty": ktyName}
	known := map[int64]bool{keyLabelKty: true}
	if kty == KeyTypeOKP || kty == KeyTypeEC2 {
		known[keyLabelCrv] = true
		var name string
		for n, c := range jwkCrv {
			if c == k.Curve() {
				name = n
			}
		}
		if name == "" {
			return nil, fmt.Errorf("%w: no JWK crv for %d", ErrInvalidKey, k.Curve())
		}
		out["crv"] = name
	}
	for _, mem := range jwkMembers[kty] {
		known[mem.label] = true
		if b, ok := k.bytesParam(mem.label); ok {
			out[mem.name] = b64.EncodeToString(b)
		}
	}
	if kid := k.ID(); kid != nil {
		known[keyLabelKid] = true
		if utf8.Valid(kid) {
			out["kid"] = string(kid)
		} else {
			out["kid"] = b64.EncodeToString(kid)
		}
	}
	if a, ok := k.Algorithm(); ok {
		known[keyLabelAlg] = true
		var name string
		for n, id := range jwkAlg {
			if id == a {
				name = n
			}
		}
		if name == "" {
			return nil, fmt.Errorf("%w: no JOSE name for alg %d", ErrUnsupportedAlgorithm, a)
		}
		out["alg"] = name
	}
	if v, ok := k.get(keyLabelKeyOps).(corecbor.Value); ok {
		known[keyLabelKeyOps] = true
		var names []string
		for _, it := range v.Items {
			if it.Kind == corecbor.KindText {
				names = append(names, it.TextVal())
				continue
			}
			op := KeyOp(it.UintVal())
			switch op {
			case KeyOpMACCreate:
				op = KeyOpSign
			case KeyOpMACVerify:
				op = KeyOpVerify
			}
			name := ""
			for n, o := range jwkOps {
				if o == op {
					name = n
				}
			}
			if name == "" {
				return nil, fmt.Errorf("%w: no JWK key_ops name for %d", ErrUnsupportedAlgorithm, op)
			}
			names = append(names, name)
		}
		out["key_ops"] = names
	}
	for label := range maps.Keys(k.params) {
		if !known[label] {
			return nil, fmt.Errorf("%w: COSE_Key label %d has no JWK equivalent", ErrUnsupportedAlgorithm, label)
		}
	}
	return json.Marshal(out)
}
