// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package receipt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
)

// RFC 9942 §4.3: receipts = [+ bstr .cbor Receipt], each a tagged
// COSE_Sign1 ("Receipts MUST be tagged as COSE_Sign1").
func TestReceiptsFraming037(t *testing.T) {
	l := newLog(t, 3)
	r := l.inclusion(t, 2, 3)
	good, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ss, _ := cose.NewSigner(priv)
	stmt := func(items []any) *cose.Sign1 {
		t.Helper()
		msg, err := ss.Sign([]byte("statement"))
		if err != nil {
			t.Fatal(err)
		}
		if items != nil {
			if err := msg.Unprotected.SetChecked(receipt.HeaderReceipts, items); err != nil {
				t.Fatal(err)
			}
		}
		return msg
	}
	if rs, err := receipt.Receipts(stmt([]any{good})); err != nil || len(rs) != 1 {
		t.Fatalf("one receipt: %v, %v", rs, err)
	}
	for name, items := range map[string][]any{
		"empty array":         {},
		"untagged receipt":    {good[1:]},
		"trailing bytes":      {append(append([]byte{}, good...), 0x00)},
		"self-describe 55799": {append([]byte{0xd9, 0xd9, 0xf7}, good...)},
		"tag 61":              {append([]byte{0xd8, 0x3d}, good...)},
	} {
		if _, err := receipt.Receipts(stmt(items)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("%s: %v, want cose.ErrMalformed", name, err)
		}
	}
	// Parse, for a receipt on its own, keeps accepting a self-described
	// top-level item.
	if _, err := receipt.Parse(append([]byte{0xd9, 0xd9, 0xf7}, good...)); err != nil {
		t.Errorf("Parse(55799(18(...))): %v", err)
	}
}
