// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package scitt_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
	"github.com/jahkeup/corecbor/scitt"
)

// FuzzParseStatement checks that ParseStatement and Verify never panic
// and that every rejection is a classified error.
func FuzzParseStatement(f *testing.F) {
	ctx := context.Background()
	issuer := newParty(f, "issuer-1")
	ts := newService(f, "ts.example", 3)
	st, err := scitt.Issue(ctx, issuer.signer, []byte("seed"), scitt.IssueOptions{Issuer: "https://i.example", Subject: "s", KeyID: issuer.kid})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(marshal(f, st.Msg))
	if err := receipt.Attach(st.Msg, ts.register(f, st, true)); err != nil {
		f.Fatal(err)
	}
	f.Add(marshal(f, st.Msg))
	f.Add([]byte{0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40})

	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := scitt.ParseStatement(data); err != nil {
			if !errors.Is(err, cose.ErrMalformed) && !errors.Is(err, cose.ErrUnsupportedAlgorithm) {
				t.Fatalf("unclassified parse error: %v", err)
			}
			return
		}
		_, _ = scitt.Verify(ctx, data, scitt.VerifyOptions{IssuerKeys: issuer.keys, ServiceKeys: ts.keys})
	})
}
