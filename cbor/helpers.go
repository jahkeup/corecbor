// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "errors"

// ErrNonStringKey is returned by Map.AsStringMap when a key is not Text.
var ErrNonStringKey = errors.New("cbor: map contains non-string key")

// AsStringMap converts a Map to map[string]Value if every key is Text.
// Returns ErrNonStringKey if any key is not a Text value.
func (m Map) AsStringMap() (map[string]Value, error) {
	result := make(map[string]Value, len(m))
	for _, entry := range m {
		key, ok := entry.Key.(Text)
		if !ok {
			return nil, ErrNonStringKey
		}
		result[string(key)] = entry.Value
	}
	return result, nil
}
