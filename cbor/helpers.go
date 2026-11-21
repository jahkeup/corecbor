// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "errors"

// ByteKey is the Go map key used when decoding into map[any]any and a
// CBOR map key is a byte string (a []byte cannot be a Go map key).
type ByteKey string

// EncodedKey is the Go map key used when decoding into map[any]any and
// a CBOR map key is an array, map, tag, null, undefined or simple
// value. The string holds the key's Core Deterministic encoding.
type EncodedKey string

// ErrNonStringKey is returned by AsStringMap when a key is not Text.
var ErrNonStringKey = errors.New("cbor: map contains non-string key")

// AsStringMap converts a map Value to map[string]Value if every key is Text.
func AsStringMap(m Value) (map[string]Value, error) {
	pairs := m.Map()
	result := make(map[string]Value, len(pairs))
	for _, entry := range pairs {
		if entry.Key.Kind != KindText {
			return nil, ErrNonStringKey
		}
		result[entry.Key.TextVal()] = entry.Value
	}
	return result, nil
}
