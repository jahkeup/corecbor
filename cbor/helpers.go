// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "errors"

// ErrNonStringKey is returned by AsStringMap when a key is not Text.
var ErrNonStringKey = errors.New("cbor: map contains non-string key")

// AsStringMap converts a map ([]MapEntry) to map[string]Value if every key is Text.
// Returns ErrNonStringKey if any key is not a Text value.
func AsStringMap(m []MapEntry) (map[string]Value, error) {
	result := make(map[string]Value, len(m))
	for _, entry := range m {
		if entry.Key.Kind() != KindText {
			return nil, ErrNonStringKey
		}
		result[entry.Key.Text()] = entry.Value
	}
	return result, nil
}
