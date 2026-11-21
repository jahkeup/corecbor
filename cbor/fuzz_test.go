// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	cc "github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

// FuzzValueString: String never panics, implements fmt.Stringer, and
// equals the root package's compact diagnostic rendering. Every decoded
// value equals itself.
func FuzzValueString(f *testing.F) {
	for _, h := range []string{
		"00", "20", "3bffffffffffffffff", "4100", "6161", "61ff", "8301820203820405",
		"a2616101616102", "c11a514b67b0", "f97e00", "fb7ff8000000000001", "f818", "f7",
		"9f01ff", "bf6161f5ff", "d8187f6161ff",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, _, err := rfc8949.Decode(data, rfc8949.DecodeOpts{})
		if err != nil {
			return
		}
		s := v.String()
		if got := fmt.Sprint(v); got != s {
			t.Fatalf("fmt.Sprint = %q, String = %q", got, s)
		}
		if want := cc.DiagnosticValue(v, cc.DiagCompact()); s != want {
			t.Fatalf("String = %q, DiagnosticValue = %q", s, want)
		}
		if !v.Equal(v) {
			t.Fatalf("value not equal to itself: %s", s)
		}
	})
}
