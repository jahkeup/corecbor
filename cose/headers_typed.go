// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // SHA-1 x5t is registered (Filter Only) and only compared, never trusted alone.
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math"

	"github.com/jahkeup/corecbor"
)

// Registered header labels with typed accessors (IANA "COSE Header
// Parameters", verified 2026-11-21).
const (
	headerLabelIV           int64 = 5   // RFC 9052
	headerLabelPartialIV    int64 = 6   // RFC 9052
	headerLabelKeyIDContext int64 = 10  // RFC 8613
	headerLabelKCWT         int64 = 13  // RFC 9528
	headerLabelKCCS         int64 = 14  // RFC 9528
	headerLabelCWTClaims    int64 = 15  // RFC 9597
	headerLabelType         int64 = 16  // RFC 9596
	headerLabelX5Bag        int64 = 32  // RFC 9360
	headerLabelX5Chain      int64 = 33  // RFC 9360
	headerLabelX5T          int64 = 34  // RFC 9360
	headerLabelX5U          int64 = 35  // RFC 9360
	headerLabel3161TTC      int64 = 269 // RFC 9921
	headerLabel3161CTT      int64 = 270 // RFC 9921
)

// value returns the parameter for label as a corecbor.Value, whether it
// was decoded (corecbor.Value for arrays and maps, Go scalars
// otherwise) or set locally with SetChecked.
func (h *Headers) value(label int64) (corecbor.Value, bool) {
	v, ok := h.params[label]
	if !ok {
		return corecbor.Value{}, false
	}
	cv, err := goToCBORChecked(v)
	if err != nil {
		return corecbor.Value{}, false
	}
	return cv, true
}

func (h *Headers) bytesParam(label int64) []byte {
	v, ok := h.value(label)
	if !ok || v.Kind != corecbor.KindBytes {
		return nil
	}
	return v.BytesVal()
}

// uintOrText reads a "uint / tstr" parameter (content type, typ).
func (h *Headers) uintOrText(label int64) (uint64, string, bool) {
	v, ok := h.value(label)
	if !ok {
		return 0, "", false
	}
	switch v.Kind {
	case corecbor.KindUint:
		return v.UintVal(), "", true
	case corecbor.KindText:
		return 0, v.TextVal(), true
	default:
		return 0, "", false
	}
}

func (h *Headers) setUintOrText(label int64, v any) error {
	switch x := v.(type) {
	case string:
		return h.SetChecked(label, x)
	case uint64:
		return h.SetChecked(label, x)
	case int:
		if x < 0 {
			return fmt.Errorf("%w: label %d must be uint or tstr, got %d", ErrUnsupportedHeader, label, x)
		}
		return h.SetChecked(label, uint64(x))
	case int64:
		if x < 0 {
			return fmt.Errorf("%w: label %d must be uint or tstr, got %d", ErrUnsupportedHeader, label, x)
		}
		return h.SetChecked(label, uint64(x))
	default:
		return fmt.Errorf("%w: label %d must be uint or tstr, got %T", ErrUnsupportedHeader, label, v)
	}
}

// Critical returns the crit header (label 2) labels, normalized to int64
// or string, or nil if absent or malformed.
func (h *Headers) Critical() []any {
	v, ok := h.value(headerLabelCritical)
	if !ok || v.Kind != corecbor.KindArray {
		return nil
	}
	out := make([]any, 0, len(v.Items))
	for _, it := range v.Items {
		l, err := labelToGo(it)
		if err != nil {
			return nil
		}
		out = append(out, l)
	}
	return out
}

// SetCritical sets the crit header (label 2, RFC 9052 §3.1). It must
// list at least one label (int or string), and belongs in the protected
// bucket.
func (h *Headers) SetCritical(labels ...any) error {
	if len(labels) == 0 {
		return fmt.Errorf("%w: crit must list at least one label", ErrUnsupportedHeader)
	}
	items := make([]any, len(labels))
	for i, l := range labels {
		n, ok := normalizeLabel(l)
		if !ok {
			return fmt.Errorf("%w: crit label of type %T", ErrUnsupportedHeader, l)
		}
		items[i] = n
	}
	return h.SetChecked(headerLabelCritical, items)
}

// ContentType returns the content type header (label 3): a CoAP
// Content-Format number or a media type string. ok is false if absent.
func (h *Headers) ContentType() (format uint64, mediaType string, ok bool) {
	return h.uintOrText(headerLabelContentType)
}

// SetContentType sets the content type header (label 3) to a
// non-negative integer (CoAP Content-Format) or a string (media type).
func (h *Headers) SetContentType(ct any) error {
	return h.setUintOrText(headerLabelContentType, ct)
}

// Type returns the typ header (label 16, RFC 9596): a CoAP
// Content-Format number or a media type string.
func (h *Headers) Type() (format uint64, mediaType string, ok bool) {
	return h.uintOrText(headerLabelType)
}

// SetType sets the typ header (label 16, RFC 9596).
func (h *Headers) SetType(typ any) error {
	return h.setUintOrText(headerLabelType, typ)
}

// IV returns the IV header (label 5), or nil.
func (h *Headers) IV() []byte { return h.bytesParam(headerLabelIV) }

// SetIV sets the IV header (label 5).
func (h *Headers) SetIV(iv []byte) error { return h.SetChecked(headerLabelIV, iv) }

// PartialIV returns the Partial IV header (label 6), or nil.
func (h *Headers) PartialIV() []byte { return h.bytesParam(headerLabelPartialIV) }

// SetPartialIV sets the Partial IV header (label 6).
func (h *Headers) SetPartialIV(piv []byte) error { return h.SetChecked(headerLabelPartialIV, piv) }

// KeyIDContext returns the kid context header (label 10, RFC 8613), or nil.
func (h *Headers) KeyIDContext() []byte { return h.bytesParam(headerLabelKeyIDContext) }

// KCWT returns the kcwt header (label 13, RFC 9528): a CWT carrying the
// key, as received.
func (h *Headers) KCWT() (corecbor.Value, bool) { return h.value(headerLabelKCWT) }

// KCCS returns the kccs header (label 14, RFC 9528): a CWT Claims Set
// carrying the key, as received.
func (h *Headers) KCCS() (corecbor.Value, bool) { return h.value(headerLabelKCCS) }

// CWTClaims returns the CWT Claims header (label 15, RFC 9597), which
// must be a map. ok is false if absent or not a map.
func (h *Headers) CWTClaims() (corecbor.Value, bool) {
	v, ok := h.value(headerLabelCWTClaims)
	if !ok || v.Kind != corecbor.KindMap {
		return corecbor.Value{}, false
	}
	return v, true
}

// SetCWTClaims sets the CWT Claims header (label 15, RFC 9597). claims
// must be a CWT Claims Set map. RFC 9597 §2 recommends the protected
// bucket.
func (h *Headers) SetCWTClaims(claims corecbor.Value) error {
	if claims.Kind != corecbor.KindMap {
		return fmt.Errorf("%w: CWT Claims must be a map, got kind %d", ErrUnsupportedHeader, claims.Kind)
	}
	return h.SetChecked(headerLabelCWTClaims, claims)
}

// x509Param reads a COSE_X509 parameter: bstr / [2* bstr] (RFC 9360 §2).
func (h *Headers) x509Param(label int64) ([][]byte, error) {
	v, ok := h.value(label)
	if !ok {
		return nil, nil
	}
	switch v.Kind {
	case corecbor.KindBytes:
		return [][]byte{v.BytesVal()}, nil
	case corecbor.KindArray:
		if len(v.Items) < 2 {
			return nil, fmt.Errorf("%w: label %d: COSE_X509 array needs at least 2 certificates", ErrMalformed, label)
		}
		out := make([][]byte, len(v.Items))
		for i, it := range v.Items {
			if it.Kind != corecbor.KindBytes {
				return nil, fmt.Errorf("%w: label %d: certificate %d is not a bstr", ErrMalformed, label, i)
			}
			out[i] = it.BytesVal()
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: label %d: COSE_X509 must be bstr or array", ErrMalformed, label)
	}
}

func (h *Headers) setX509Param(label int64, der [][]byte) error {
	switch len(der) {
	case 0:
		return fmt.Errorf("%w: label %d needs at least one certificate", ErrUnsupportedHeader, label)
	case 1:
		return h.SetChecked(label, der[0])
	default:
		items := make([]any, len(der))
		for i, d := range der {
			items[i] = d
		}
		return h.SetChecked(label, items)
	}
}

// X5Chain returns the x5chain header (label 33, RFC 9360): DER
// certificates, leaf first. A single bstr and an array are both
// accepted; absent is (nil, nil). Chain validation is the caller's job.
func (h *Headers) X5Chain() ([][]byte, error) { return h.x509Param(headerLabelX5Chain) }

// SetX5Chain sets the x5chain header (label 33), leaf first. One
// certificate is written as a bstr, more as an array (RFC 9360 §2).
func (h *Headers) SetX5Chain(der ...[]byte) error { return h.setX509Param(headerLabelX5Chain, der) }

// X5Bag returns the x5bag header (label 32, RFC 9360): an unordered set
// of DER certificates.
func (h *Headers) X5Bag() ([][]byte, error) { return h.x509Param(headerLabelX5Bag) }

// SetX5Bag sets the x5bag header (label 32).
func (h *Headers) SetX5Bag(der ...[]byte) error { return h.setX509Param(headerLabelX5Bag, der) }

// X5U returns the x5u header (label 35, RFC 9360): a URI for the
// certificate chain.
func (h *Headers) X5U() (string, bool) {
	v, ok := h.value(headerLabelX5U)
	if !ok || v.Kind != corecbor.KindText {
		return "", false
	}
	return v.TextVal(), true
}

// SetX5U sets the x5u header (label 35).
func (h *Headers) SetX5U(uri string) error { return h.SetChecked(headerLabelX5U, uri) }

// CertHash is a COSE_CertHash (RFC 9360 §2): a hash algorithm and the
// hash of a DER certificate.
type CertHash struct {
	Alg  Algorithm // a hash algorithm, e.g. AlgSHA256
	Hash []byte
}

// Matches reports whether cert (DER) hashes to h. An unsupported hash
// algorithm never matches.
func (h CertHash) Matches(cert []byte) bool {
	var sum []byte
	switch h.Alg {
	case AlgSHA1:
		s := sha1.Sum(cert) //nolint:gosec // see import comment
		sum = s[:]
	case AlgSHA256_64:
		s := sha256.Sum256(cert)
		sum = s[:8]
	case AlgSHA256:
		s := sha256.Sum256(cert)
		sum = s[:]
	case AlgSHA512_256:
		s := sha512.Sum512_256(cert)
		sum = s[:]
	case AlgSHA384:
		s := sha512.Sum384(cert)
		sum = s[:]
	case AlgSHA512:
		s := sha512.Sum512(cert)
		sum = s[:]
	default:
		return false
	}
	return bytes.Equal(sum, h.Hash)
}

// X5T returns the x5t header (label 34, RFC 9360). ok is false if
// absent; a present but malformed value is ErrMalformed. A text hash
// algorithm identifier is reported as ErrUnsupportedAlgorithm.
func (h *Headers) X5T() (CertHash, bool, error) {
	v, ok := h.value(headerLabelX5T)
	if !ok {
		return CertHash{}, false, nil
	}
	if v.Kind != corecbor.KindArray || len(v.Items) != 2 || v.Items[1].Kind != corecbor.KindBytes {
		return CertHash{}, true, fmt.Errorf("%w: x5t must be [hashAlg, bstr]", ErrMalformed)
	}
	var alg Algorithm
	switch a := v.Items[0]; a.Kind {
	case corecbor.KindUint:
		if a.UintVal() > math.MaxInt64 {
			return CertHash{}, true, fmt.Errorf("%w: x5t hash algorithm out of range", ErrMalformed)
		}
		alg = Algorithm(a.UintVal())
	case corecbor.KindNegInt:
		if a.NegIntVal() > math.MaxInt64 {
			return CertHash{}, true, fmt.Errorf("%w: x5t hash algorithm out of range", ErrMalformed)
		}
		alg = Algorithm(-1 - int64(a.NegIntVal()))
	case corecbor.KindText:
		return CertHash{}, true, fmt.Errorf("%w: x5t hash algorithm %q", ErrUnsupportedAlgorithm, a.TextVal())
	default:
		return CertHash{}, true, fmt.Errorf("%w: x5t hash algorithm must be int or tstr", ErrMalformed)
	}
	return CertHash{Alg: alg, Hash: v.Items[1].BytesVal()}, true, nil
}

// SetX5T sets the x5t header (label 34) to [alg, hash].
func (h *Headers) SetX5T(alg Algorithm, hash []byte) error {
	return h.SetChecked(headerLabelX5T, []any{int64(alg), hash})
}

// TimestampTTC returns the 3161-ttc header (label 269, RFC 9921): an
// RFC 3161 timestamp token over the signature ("timestamp then COSE").
func (h *Headers) TimestampTTC() []byte { return h.bytesParam(headerLabel3161TTC) }

// TimestampCTT returns the 3161-ctt header (label 270, RFC 9921): an
// RFC 3161 timestamp token over the COSE structure ("COSE then
// timestamp").
func (h *Headers) TimestampCTT() []byte { return h.bytesParam(headerLabel3161CTT) }

// Lookup returns label's value from a layer's buckets, protected first.
// RFC 9052 §3 forbids a label in both buckets, and decoding rejects it.
// A value from the unprotected bucket is not integrity protected: treat
// it as a hint (for example a kid used only to select a key).
func Lookup(protected, unprotected *Headers, label any) (any, bool) {
	n, ok := normalizeLabel(label)
	if !ok {
		return nil, false
	}
	if protected != nil {
		if v, ok := protected.params[n]; ok {
			return v, true
		}
	}
	if unprotected != nil {
		if v, ok := unprotected.params[n]; ok {
			return v, true
		}
	}
	return nil, false
}
