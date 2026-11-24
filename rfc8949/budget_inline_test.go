// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// TestBudgetInlineMatchesChecked: with a memory budget, short strings
// and map keys keep the inline fast paths and are charged exactly as the
// checked path charges them, so the same budget accepts or rejects the
// same input either way.
func TestBudgetInlineMatchesChecked(t *testing.T) {
	src := mustHex("a3" + "616161" + "6362626262" + "6163" + "43010203" + "6164" + "82626566" + "4100")
	need := -1
	for limit := 1; limit < 4096; limit++ {
		_, _, err := Decode(src, DecodeOpts{Budget: NewBudget(limit)})
		if err == nil {
			need = limit
			break
		}
		if !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
			t.Fatalf("limit %d: %v", limit, err)
		}
	}
	if need < 0 {
		t.Fatal("no budget fits")
	}
	// MaxByteStringLength under 24 forces the checked path everywhere.
	checked := func(limit int) error {
		_, _, err := Decode(src, DecodeOpts{Budget: NewBudget(limit), MaxByteStringLength: 20})
		return err
	}
	if err := checked(need); err != nil {
		t.Errorf("checked path at the inline path's minimum %d: %v", need, err)
	}
	if err := checked(need - 1); !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Errorf("checked path under the minimum: %v, want ErrMemoryBudgetExceeded", err)
	}
}
