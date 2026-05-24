// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

// StringInterner deduplicates decoded text strings. When the decoder
// encounters a text string matching an existing entry, it reuses the
// interned string (zero allocation) instead of allocating a new one.
// Not goroutine-safe — use one per goroutine or per decode call.
type StringInterner struct {
	table map[string]string
	max   int
}

// NewStringInterner creates an interner with maxEntries capacity.
// When full, new strings are allocated normally (graceful degradation).
func NewStringInterner(maxEntries int) *StringInterner {
	return &StringInterner{
		table: make(map[string]string, min(maxEntries, 256)),
		max:   maxEntries,
	}
}

// Prefill seeds the interner with known-frequent strings that are
// never evicted.
func (si *StringInterner) Prefill(keys ...string) {
	for _, k := range keys {
		si.table[k] = k
	}
}

// Intern returns the interned copy of the string represented by raw
// bytes. If the string is already in the table, returns the existing
// copy (zero allocation for the string itself).
func (si *StringInterner) Intern(raw []byte) string {
	if existing, ok := si.table[string(raw)]; ok {
		return existing
	}
	if len(si.table) >= si.max {
		return string(raw)
	}
	s := string(raw)
	si.table[s] = s
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
