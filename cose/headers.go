// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"github.com/jahkeup/corecbor"
)

// COSE header labels (integer keys per RFC 9052 §3.1).
const (
	headerLabelAlgorithm   int64 = 1
	headerLabelCritical    int64 = 2
	headerLabelContentType int64 = 3
	headerLabelKeyID       int64 = 4
)

// Headers represents COSE header parameters.
// Keys are int64 (integer labels) or string (text labels).
type Headers struct {
	params       map[any]any
	encodedCache []byte // cached CBOR encoding of protected headers
	cacheValid   bool
}

// Get returns the value for the given label, or nil if not set.
func (h *Headers) Get(label any) any {
	if h.params == nil {
		return nil
	}
	return h.params[label]
}

// Set sets a header parameter.
func (h *Headers) Set(label any, value any) {
	if h.params == nil {
		h.params = make(map[any]any)
	}
	h.params[label] = value
	h.cacheValid = false
}

// Algorithm returns the algorithm header (label 1), or 0 if not set.
func (h *Headers) Algorithm() Algorithm {
	v := h.Get(headerLabelAlgorithm)
	if v == nil {
		return 0
	}
	switch a := v.(type) {
	case int64:
		return Algorithm(a)
	case Algorithm:
		return a
	default:
		return 0
	}
}

// SetAlgorithm sets the algorithm header (label 1).
func (h *Headers) SetAlgorithm(alg Algorithm) {
	h.Set(headerLabelAlgorithm, int64(alg))
}

// KeyID returns the key ID header (label 4), or nil if not set.
func (h *Headers) KeyID() []byte {
	v := h.Get(headerLabelKeyID)
	if v == nil {
		return nil
	}
	if b, ok := v.([]byte); ok {
		return b
	}
	return nil
}

// SetKeyID sets the key ID header (label 4).
func (h *Headers) SetKeyID(kid []byte) {
	h.Set(headerLabelKeyID, kid)
}

// IsEmpty returns true if there are no parameters.
func (h *Headers) IsEmpty() bool {
	return len(h.params) == 0
}

// encodeProtected serializes protected headers to CBOR bytes.
// Empty headers produce a zero-length byte string.
func (h *Headers) encodeProtected() ([]byte, error) {
	if h.IsEmpty() {
		return nil, nil
	}
	if h.cacheValid {
		return h.encodedCache, nil
	}
	encoded, err := encodeHeaderMap(h.params)
	if err != nil {
		return nil, err
	}
	h.encodedCache = encoded
	h.cacheValid = true
	return encoded, nil
}

// toCBORMap converts headers to a corecbor map Value.
func (h *Headers) toCBORMap() corecbor.Value {
	if h.IsEmpty() {
		return corecbor.MakeMap()
	}
	return headerParamsToMap(h.params)
}

// headerParamsToMap converts a Go map to a corecbor map Value.
func headerParamsToMap(params map[any]any) corecbor.Value {
	if len(params) == 0 {
		return corecbor.Value{}
	}
	m := make([]corecbor.MapEntry, 0, len(params))
	for k, v := range params {
		m = append(m, corecbor.MapEntry{
			Key:   goToCBOR(k),
			Value: goToCBOR(v),
		})
	}
	return corecbor.MakeMapFromSlice(m)
}

// encodeHeaderMap encodes a header map to CBOR bytes using CoreDeterministic.
func encodeHeaderMap(params map[any]any) ([]byte, error) {
	m := headerParamsToMap(params)
	return sharedEncoder.Encode(nil, m)
}

// decodeProtected decodes CBOR-encoded protected headers.
func decodeProtected(data []byte) (*Headers, error) {
	if len(data) == 0 {
		return &Headers{}, nil
	}
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.Kind == corecbor.KindMap, v.Kind == corecbor.KindMap
	if !ok {
		return nil, ErrMalformed
	}
	pairs := v.Map()
	h := &Headers{params: make(map[any]any, len(pairs))}
	for _, entry := range pairs {
		key := cborToGo(entry.Key)
		val := cborToGo(entry.Value)
		h.params[key] = val
	}
	_ = m
	return h, nil
}

// decodeUnprotected decodes an unprotected header CBOR map value.
func decodeUnprotected(v corecbor.Value) (*Headers, error) {
	if v.IsZero() {
		return &Headers{}, nil
	}
	if v.Kind != corecbor.KindMap {
		return nil, ErrMalformed
	}
	m := v.Map()
	if len(m) == 0 {
		return &Headers{}, nil
	}
	h := &Headers{params: make(map[any]any, len(m))}
	for _, entry := range m {
		key := cborToGo(entry.Key)
		val := cborToGo(entry.Value)
		h.params[key] = val
	}
	return h, nil
}

// goToCBOR converts a Go value to a corecbor Value.
func goToCBOR(v any) corecbor.Value {
	switch x := v.(type) {
	case int64:
		if x >= 0 {
			return corecbor.Uint(uint64(x))
		}
		return corecbor.NegInt(uint64(-1 - x))
	case uint64:
		return corecbor.Uint(x)
	case int:
		if x >= 0 {
			return corecbor.Uint(uint64(x))
		}
		return corecbor.NegInt(uint64(-1 - x))
	case string:
		return corecbor.Text(x)
	case []byte:
		return corecbor.Bytes(x)
	case bool:
		return corecbor.Bool(x)
	case nil:
		return corecbor.Null()
	default:
		if cv, ok := v.(corecbor.Value); ok {
			return cv
		}
		return corecbor.Null()
	}
}

// cborToGo converts a corecbor Value to a Go value.
func cborToGo(v corecbor.Value) any {
	switch v.Kind {
	case corecbor.KindUint:
		return int64(v.UintVal())
	case corecbor.KindNegInt:
		return int64(-1 - int64(v.NegIntVal()))
	case corecbor.KindText:
		return v.TextVal()
	case corecbor.KindBytes:
		return v.BytesVal()
	case corecbor.KindBool:
		return v.BoolVal()
	case corecbor.KindNull:
		return nil
	default:
		return v
	}
}
