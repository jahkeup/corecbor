// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"errors"
	"testing"
)

// Proposal 037 S19: COSE_Encrypt and COSE_Mac need at least one
// recipient, and COSE_Sign at least one signature (RFC 9052 §4.1, §5.1,
// §6.1: [+COSE_recipient], [+COSE_Signature]).
func TestSpec037EmptyRecipientsAndSignatures(t *testing.T) {
	for name, c := range map[string]struct {
		data   string
		decode func([]byte) error
	}{
		"Encrypt": {"d860" + "84" + "40" + "a0" + "40" + "80", func(b []byte) error { _, err := UnmarshalEncrypt(b); return err }},
		"Mac":     {"d861" + "85" + "40" + "a0" + "40" + "40" + "80", func(b []byte) error { _, err := UnmarshalMac(b); return err }},
		"Sign":    {"d862" + "84" + "40" + "a0" + "40" + "80", func(b []byte) error { _, err := UnmarshalSign(b); return err }},
	} {
		t.Run(name, func(t *testing.T) {
			if err := c.decode(hx(t, c.data)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}
