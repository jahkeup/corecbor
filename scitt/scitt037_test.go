// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package scitt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cose"
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

// issueReceipt is service.register with control over the headers.
func issueReceipt(t *testing.T, ts *service, st *scitt.Statement, kid bool, unprotClaims bool) *receipt.Receipt {
	t.Helper()
	entry, err := scitt.Entry(st.Msg)
	if err != nil {
		t.Fatal(err)
	}
	idx := ts.tree.Append(entry)
	size := ts.tree.Size()
	p, _ := ts.tree.InclusionProof(idx, size)
	root, _ := ts.tree.Root(size)
	prot, err := scitt.ReceiptHeaders(ts.iss, "statement")
	if err != nil {
		t.Fatal(err)
	}
	if kid {
		prot.SetKeyID(ts.kid)
	}
	r, err := receipt.Issue(context.Background(), ts.signer, root, p, prot)
	if err != nil {
		t.Fatal(err)
	}
	if unprotClaims {
		if err := cwt.SetClaimsHeader(&r.Msg.Unprotected, &cwt.ClaimsSet{Issuer: "other.example", Subject: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// W28: RFC 9943 §6 — a receipt is a signed statement: its CWT Claims are
// protected only, and it carries a protected kid unless x5t or x5chain
// identifies the service.
func TestReceiptHeaders037(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	ts := newService(t, "ts.example", 3)
	for name, tc := range map[string]struct{ kid, unprot, ok bool }{
		"protected kid":               {kid: true, ok: true},
		"no kid":                      {kid: false},
		"CWT Claims also unprotected": {kid: true, unprot: true},
	} {
		st := issueWith(t, issuer, nil)
		if err := receipt.Attach(st.Msg, issueReceipt(t, ts, st, tc.kid, tc.unprot)); err != nil {
			t.Fatal(err)
		}
		_, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, ts.keys, 1)
		// Label 15 in both buckets is already malformed COSE (RFC 9052 §3).
		if tc.ok != (err == nil) || (!tc.ok && !tc.unprot && !errors.Is(err, scitt.ErrInsufficientReceipts)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A receipt's own validity period (exp, nbf in its protected CWT Claims)
// is checked with the same validator as the statement's.
func TestReceiptValidity037(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	ts := newService(t, "ts.example", 3)
	now := time.Now()
	withClaims := func(st *scitt.Statement, rc *cwt.ClaimsSet) *receipt.Receipt {
		t.Helper()
		entry, _ := scitt.Entry(st.Msg)
		idx := ts.tree.Append(entry)
		size := ts.tree.Size()
		p, _ := ts.tree.InclusionProof(idx, size)
		root, _ := ts.tree.Root(size)
		var prot cose.Headers
		if err := cwt.SetClaimsHeader(&prot, rc); err != nil {
			t.Fatal(err)
		}
		prot.SetKeyID(ts.kid)
		r, err := receipt.Issue(ctx, ts.signer, root, p, prot)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	verify := func(rc *cwt.ClaimsSet, v *cwt.Validator) error {
		st := issueWith(t, issuer, nil)
		if err := receipt.Attach(st.Msg, withClaims(st, rc)); err != nil {
			t.Fatal(err)
		}
		_, err := scitt.Verify(ctx, marshal(t, st.Msg), scitt.VerifyOptions{IssuerKeys: issuer.keys, ServiceKeys: ts.keys, Validator: v})
		return err
	}
	base := func() *cwt.ClaimsSet { return &cwt.ClaimsSet{Issuer: ts.iss, Subject: "statement"} }
	expired := base()
	expired.Expiration = now.Add(-time.Hour)
	if err := verify(expired, nil); !errors.Is(err, scitt.ErrInsufficientReceipts) || !errors.Is(err, cwt.ErrTokenExpired) {
		t.Errorf("expired receipt: %v, want ErrInsufficientReceipts wrapping cwt.ErrTokenExpired", err)
	}
	early := base()
	early.NotBefore = now.Add(time.Hour)
	if err := verify(early, nil); !errors.Is(err, cwt.ErrTokenNotYetValid) {
		t.Errorf("not-yet-valid receipt: %v", err)
	}
	valid := base()
	valid.Expiration = now.Add(time.Hour)
	if err := verify(valid, nil); err != nil {
		t.Errorf("valid receipt: %v", err)
	}
	past := &cwt.Validator{Now: func() time.Time { return now.Add(-2 * time.Hour) }}
	if err := verify(expired, past); err != nil {
		t.Errorf("expired receipt, Validator.Now in its window: %v", err)
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
