// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package scitt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose/receipt"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/scitt"
)

// Proposal 037 tests.

func issueWith(t *testing.T, issuer *party, claims *cwt.ClaimsSet) *scitt.Statement {
	t.Helper()
	st, err := scitt.Issue(context.Background(), issuer.signer, []byte("payload"), scitt.IssueOptions{
		Issuer: "https://issuer.example", Subject: "pkg:example/widget@1.0", KeyID: issuer.kid, Claims: claims,
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// W5: MinReceipts counts distinct receipt issuers, not receipts.
func TestMinReceipts_Distinct037(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	ts1 := newService(t, "ts1.example", 3)
	ts2 := newService(t, "ts2.example", 3)
	both := multiResolver{ts1.keys, ts2.keys}

	// The same receipt attached twice.
	st := issueWith(t, issuer, nil)
	r := ts1.register(t, st, true)
	if err := receipt.Attach(st.Msg, r, r); err != nil {
		t.Fatal(err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, both, 2); !errors.Is(err, scitt.ErrInsufficientReceipts) {
		t.Errorf("duplicate receipt, min 2: %v, want ErrInsufficientReceipts", err)
	}

	// Two receipts from one service (registered twice).
	st = issueWith(t, issuer, nil)
	if err := receipt.Attach(st.Msg, ts1.register(t, st, true), ts1.register(t, st, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, both, 2); !errors.Is(err, scitt.ErrInsufficientReceipts) {
		t.Errorf("two receipts from one service, min 2: %v, want ErrInsufficientReceipts", err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, both, 1); err != nil {
		t.Errorf("min 1: %v", err)
	}

	// Two services.
	st = issueWith(t, issuer, nil)
	if err := receipt.Attach(st.Msg, ts1.register(t, st, true), ts2.register(t, st, true), ts1.register(t, st, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, both, 2); err != nil {
		t.Errorf("two services, min 2: %v", err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, both, 3); !errors.Is(err, scitt.ErrInsufficientReceipts) {
		t.Errorf("two services, min 3: %v, want ErrInsufficientReceipts", err)
	}
}

// W11: RFC 9943 §7.1 — the statement's validity period (exp, nbf) is
// checked by default.
func TestVerify_StatementValidity037(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	ts := newService(t, "ts.example", 3)
	now := time.Now()
	verify := func(claims *cwt.ClaimsSet, v *cwt.Validator) error {
		st := issueWith(t, issuer, claims)
		if err := receipt.Attach(st.Msg, ts.register(t, st, true)); err != nil {
			t.Fatal(err)
		}
		_, err := scitt.Verify(ctx, marshal(t, st.Msg), scitt.VerifyOptions{IssuerKeys: issuer.keys, ServiceKeys: ts.keys, Validator: v})
		return err
	}
	if err := verify(&cwt.ClaimsSet{Expiration: now.Add(-time.Hour)}, nil); !errors.Is(err, cwt.ErrTokenExpired) {
		t.Errorf("expired statement: %v, want cwt.ErrTokenExpired", err)
	}
	if err := verify(&cwt.ClaimsSet{NotBefore: now.Add(time.Hour)}, nil); !errors.Is(err, cwt.ErrTokenNotYetValid) {
		t.Errorf("not-yet-valid statement: %v, want cwt.ErrTokenNotYetValid", err)
	}
	if err := verify(&cwt.ClaimsSet{Expiration: now.Add(time.Hour), NotBefore: now.Add(-time.Hour)}, nil); err != nil {
		t.Errorf("valid statement: %v", err)
	}
	if err := verify(&cwt.ClaimsSet{IssuedAt: now}, nil); err != nil {
		t.Errorf("statement without exp: %v", err)
	}
	// An auditor checks an expired statement as of a past time.
	past := &cwt.Validator{Now: func() time.Time { return now.Add(-2 * time.Hour) }}
	if err := verify(&cwt.ClaimsSet{Expiration: now.Add(-time.Hour)}, past); err != nil {
		t.Errorf("Validator.Now in the validity window: %v", err)
	}
}
