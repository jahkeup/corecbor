// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"fmt"
	"maps"
	"math"

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
//
// Headers decoded from a message keep the protected bucket's bytes as
// received, and signatures, MACs and AEAD tags are computed over those
// bytes (RFC 9052 §4.4, §5.3, §6.3). Modifying the headers with Set
// discards them, and the headers are re-encoded deterministically.
//
// Headers are safe for concurrent reads, including concurrent
// verification of one message, but not for concurrent modification.
// Copying a Headers value is safe: Set and SetChecked never modify a
// parameter map another copy may share.
type Headers struct {
	params map[any]any
	raw    []byte // protected bucket bytes as received; nil if locally built
}

// Get returns the value for the given label, or nil if not set. Integer
// labels match regardless of Go integer type (1 and int64(1) are the
// same label).
func (h *Headers) Get(label any) any {
	if h.params == nil {
		return nil
	}
	if n, ok := normalizeLabel(label); ok {
		label = n
	}
	return h.params[label]
}

// Set sets a header parameter. Integer labels are stored as int64. Every
// value type SetChecked accepts is encoded correctly (Set(1, AlgES256)
// stores alg -7). A label or value that can't be encoded is kept, and
// the next Marshal* of a message carrying these headers returns
// ErrUnsupportedHeader instead of writing null. Set discards Raw().
//
// Deprecated: use SetChecked, which reports an unencodable label or
// value at the call site. Set is kept with its v0.2.2 signature.
func (h *Headers) Set(label any, value any) {
	if n, ok := normalizeLabel(label); ok {
		label = n
	}
	h.put(label, value)
}

// SetChecked sets a header parameter after checking that it can be
// encoded. Labels: int, int64 or string. Values: int, int64, uint64,
// Algorithm, string, []byte, bool, nil (CBOR null), corecbor.Value, or
// []any of these. It returns ErrUnsupportedHeader otherwise and leaves
// the headers unchanged. SetChecked discards Raw().
func (h *Headers) SetChecked(label any, value any) error {
	n, ok := normalizeLabel(label)
	if !ok {
		return fmt.Errorf("%w: label of type %T (want int or string)", ErrUnsupportedHeader, label)
	}
	if _, err := goToCBORChecked(value); err != nil {
		return fmt.Errorf("label %v: %w", n, err)
	}
	h.put(n, value)
	return nil
}

// put stores value under label in a fresh copy of the parameter map, so
// a Headers value copied before the call (which shares the old map)
// keeps its parameters and its Raw() bytes consistent.
func (h *Headers) put(label, value any) {
	params := maps.Clone(h.params)
	if params == nil {
		params = make(map[any]any, 1)
	}
	params[label] = value
	h.params = params
	h.raw = nil
}

// Raw returns the protected bucket bytes these headers were decoded
// from, or nil for headers built locally or modified since decoding.
// The returned slice must not be modified.
func (h *Headers) Raw() []byte {
	return h.raw
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

// encodeProtected returns the protected bucket bytes: the bytes as
// received for decoded headers, otherwise a deterministic encoding.
// With no protected parameters it returns a zero-length byte string,
// which is what RFC 9052 §4.4, §5.3 and §6.3 put in the signed and
// authenticated structures even when the sender encoded h'a0' (§3).
// It does not modify h, so concurrent verification of one message is
// race-free.
func (h *Headers) encodeProtected() ([]byte, error) {
	if h.IsEmpty() {
		return nil, nil
	}
	if h.raw != nil {
		return h.raw, nil
	}
	return encodeHeaderMap(h.params)
}

// toCBORMap converts headers to a corecbor map Value.
func (h *Headers) toCBORMap() (corecbor.Value, error) {
	if h.IsEmpty() {
		return corecbor.MakeMap(), nil
	}
	return headerParamsToMap(h.params)
}

// headerParamsToMap converts a Go map to a corecbor map Value. A label
// that isn't int64 or string, or a value with no CBOR encoding, is
// ErrUnsupportedHeader (v0.2.2 wrote null for such values).
func headerParamsToMap(params map[any]any) (corecbor.Value, error) {
	if len(params) == 0 {
		return corecbor.Value{}, nil
	}
	m := make([]corecbor.MapEntry, 0, len(params))
	for k, v := range params {
		var key corecbor.Value
		switch x := k.(type) {
		case int64, string:
			key = goToCBOR(x)
		default:
			return corecbor.Value{}, fmt.Errorf("%w: label of type %T (want int or string)", ErrUnsupportedHeader, k)
		}
		val, err := goToCBORChecked(v)
		if err != nil {
			return corecbor.Value{}, fmt.Errorf("label %v: %w", k, err)
		}
		m = append(m, corecbor.MapEntry{Key: key, Value: val})
	}
	return corecbor.MakeMapFromSlice(m), nil
}

// encodeHeaderMap encodes a header map to CBOR bytes using CoreDeterministic.
func encodeHeaderMap(params map[any]any) ([]byte, error) {
	m, err := headerParamsToMap(params)
	if err != nil {
		return nil, err
	}
	return sharedEncoder.Encode(nil, m)
}

// decodeProtected decodes CBOR-encoded protected headers and keeps data
// as the headers' raw bytes.
func decodeProtected(data []byte, lim DecodeLimits) (*Headers, error) {
	if len(data) == 0 {
		return &Headers{}, nil
	}
	v, err := newMessageDecoder(lim).Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}
	if v.Kind != corecbor.KindMap {
		return nil, ErrMalformed
	}
	h, err := headersFromPairs(v.Map(), lim.AllowDuplicateLabels)
	if err != nil {
		return nil, err
	}
	h.raw = data
	return h, nil
}

// newMessageDecoder returns the decoder for COSE messages and protected
// header maps under lim. Header maps are the only maps in a COSE
// structure, and a repeated label is invalid (RFC 9052 §3, RFC 8949
// §5.6), so duplicate keys are rejected instead of resolved last-wins
// unless lim.AllowDuplicateLabels restores v0.2.2 behavior.
func newMessageDecoder(lim DecodeLimits) *corecbor.Decoder {
	var opts []corecbor.DecoderOption
	if !lim.AllowDuplicateLabels {
		opts = append(opts, corecbor.RejectDuplicateMapKeys())
	}
	if lim.MemoryBudget > 0 {
		opts = append(opts, corecbor.WithMemoryBudget(lim.MemoryBudget))
	}
	if lim.MaxDepth > 0 {
		opts = append(opts, corecbor.WithMaxNestingDepth(lim.MaxDepth))
	}
	return corecbor.NewDecoder(opts...)
}

// decodeError wraps a core decode error as ErrMalformed, keeping it in
// the chain, and reports a duplicate map key as ErrDuplicateLabel.
func decodeError(err error) error {
	if errors.Is(err, corecbor.ErrDuplicateMapKey) {
		return fmt.Errorf("%w: %w: %w", ErrMalformed, ErrDuplicateLabel, err)
	}
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}

// decodeUnprotected decodes an unprotected header CBOR map value.
func decodeUnprotected(v corecbor.Value, allowDup bool) (*Headers, error) {
	if v.IsZero() {
		return &Headers{}, nil
	}
	if v.Kind != corecbor.KindMap {
		return nil, ErrMalformed
	}
	return headersFromPairs(v.Map(), allowDup)
}

func headersFromPairs(pairs []corecbor.MapEntry, allowDup bool) (*Headers, error) {
	if len(pairs) == 0 {
		return &Headers{}, nil
	}
	h := &Headers{params: make(map[any]any, len(pairs))}
	for _, entry := range pairs {
		key, err := labelToGo(entry.Key)
		if err != nil {
			return nil, err
		}
		// Labels compare as values, so 01 and 1801 are the same label.
		if _, dup := h.params[key]; dup && !allowDup {
			return nil, fmt.Errorf("%w: label %v", ErrDuplicateLabel, key)
		}
		h.params[key] = cborToGo(entry.Value)
	}
	return h, nil
}

// decodeBuckets decodes one layer's protected bstr and unprotected map
// and rejects a label present in both (RFC 9052 §3: "the same header
// label MUST NOT occur in both the protected and unprotected
// buckets").
func decodeBuckets(protected []byte, unprotected corecbor.Value, lim DecodeLimits) (*Headers, *Headers, error) {
	prot, err := decodeProtected(protected, lim)
	if err != nil {
		return nil, nil, err
	}
	unprot, err := decodeUnprotected(unprotected, lim.AllowDuplicateLabels)
	if err != nil {
		return nil, nil, err
	}
	if lim.AllowDuplicateLabels {
		return prot, unprot, nil
	}
	for label := range unprot.params {
		if _, dup := prot.params[label]; dup {
			return nil, nil, fmt.Errorf("%w: label %v in both buckets", ErrDuplicateLabel, label)
		}
	}
	return prot, unprot, nil
}

// labelToGo converts a header label. COSE labels are int or tstr
// (RFC 9052 §3); anything else, or an int outside the int64 range, is
// malformed.
func labelToGo(k corecbor.Value) (any, error) {
	switch k.Kind {
	case corecbor.KindUint:
		if k.UintVal() > math.MaxInt64 {
			return nil, fmt.Errorf("%w: header label %d out of range", ErrMalformed, k.UintVal())
		}
		return int64(k.UintVal()), nil
	case corecbor.KindNegInt:
		if k.NegIntVal() > math.MaxInt64 {
			return nil, fmt.Errorf("%w: header label -1-%d out of range", ErrMalformed, k.NegIntVal())
		}
		return -1 - int64(k.NegIntVal()), nil
	case corecbor.KindText:
		return k.TextVal(), nil
	default:
		return nil, fmt.Errorf("%w: header label must be int or tstr", ErrMalformed)
	}
}

// goToCBORChecked converts a header value to a corecbor Value, or
// returns ErrUnsupportedHeader for a type with no encoding here.
func goToCBORChecked(v any) (corecbor.Value, error) {
	switch x := v.(type) {
	case int64:
		return goToCBOR(x), nil
	case int:
		return goToCBOR(int64(x)), nil
	case int32:
		return goToCBOR(int64(x)), nil
	case uint64:
		return corecbor.Uint(x), nil
	case uint32:
		return corecbor.Uint(uint64(x)), nil
	case Algorithm:
		return goToCBOR(int64(x)), nil
	case string:
		return corecbor.Text(x), nil
	case []byte:
		return corecbor.Bytes(x), nil
	case bool:
		return corecbor.Bool(x), nil
	case nil:
		return corecbor.Null(), nil
	case corecbor.Value:
		return x, nil
	case []any:
		items := make([]corecbor.Value, len(x))
		for i, it := range x {
			c, err := goToCBORChecked(it)
			if err != nil {
				return corecbor.Value{}, err
			}
			items[i] = c
		}
		return corecbor.MakeArrayFromSlice(items), nil
	default:
		return corecbor.Value{}, fmt.Errorf("%w: value of type %T", ErrUnsupportedHeader, v)
	}
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
		if v.UintVal() > math.MaxInt64 {
			return v // out of int64 range: keep the exact value
		}
		return int64(v.UintVal())
	case corecbor.KindNegInt:
		if v.NegIntVal() > math.MaxInt64 {
			return v
		}
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
