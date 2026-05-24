// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "errors"

// ErrNonStringKey is returned by AsStringMap when a key is not Text.
var ErrNonStringKey = errors.New("cbor: map contains non-string key")

// AsStringMap converts a map Value to map[string]Value if every key is Text.
func AsStringMap(m Value) (map[string]Value, error) {
	pairs := m.Map()
	result := make(map[string]Value, len(pairs))
	for _, entry := range pairs {
		if entry.Key.Kind() != KindText {
			return nil, ErrNonStringKey
		}
		result[entry.Key.TextVal()] = entry.Value
	}
	return result, nil
}
