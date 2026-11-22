// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package scitt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/scitt"
)

type party struct {
	signer *cose.Signer
	keys   cose.KeyResolver
	kid    []byte
}

func newParty(t testing.TB, kid string, opts ...cose.SignerOption) *party {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cose.NewSigner(priv, opts...)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cose.NewKeyFromPublic(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.SetID([]byte(kid))
	return &party{signer: s, keys: cose.KeySetResolver(cose.KeySet{k}), kid: []byte(kid)}
}

// service is a toy transparency service: it appends Entry(stmt) to a
// Merkle tree and issues an RFC9162_SHA256 receipt for it.
type service struct {
	*party
	tree receipt.Tree
	iss  string
}

func newService(t testing.TB, iss string, fill int) *service {
	t.Helper()
	ts := &service{party: newParty(t, "ts-"+iss), iss: iss}
	for i := range fill {
		ts.tree.Append([]byte(fmt.Sprintf("%s-other-%d", iss, i)))
	}
	return ts
}

func (ts *service) register(t testing.TB, st *scitt.Statement, claims bool) *receipt.Receipt {
	t.Helper()
	entry, err := scitt.Entry(st.Msg)
	if err != nil {
		t.Fatal(err)
	}
	idx := ts.tree.Append(entry)
	ts.tree.Append([]byte("later"))
	size := ts.tree.Size()
	p, err := ts.tree.InclusionProof(idx, size)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ts.tree.Root(size)
	if err != nil {
		t.Fatal(err)
	}
	var prot cose.Headers
	if claims {
		prot, err = scitt.ReceiptHeaders(ts.iss, "statement")
		if err != nil {
			t.Fatal(err)
		}
	}
	prot.SetKeyID(ts.kid)
	r, err := receipt.Issue(context.Background(), ts.signer, root, p, prot)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func marshal(t testing.TB, msg *cose.Sign1) []byte {
	t.Helper()
	b, err := cose.MarshalSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSCITTEndToEnd: issue a signed statement, register it with two
// services, attach both receipts, and verify the transparent statement.
func TestSCITTEndToEnd(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	st, err := scitt.Issue(ctx, issuer.signer, []byte(`{"sbom":true}`), scitt.IssueOptions{
		Issuer:      "https://issuer.example",
		Subject:     "pkg:example/widget@1.0",
		ContentType: "application/json",
		Type:        "application/example+cose",
		KeyID:       issuer.kid,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts1 := newService(t, "ts1.example", 20)
	ts2 := newService(t, "ts2.example", 5)
	if err := receipt.Attach(st.Msg, ts1.register(t, st, true), ts2.register(t, st, true)); err != nil {
		t.Fatal(err)
	}
	data := marshal(t, st.Msg)

	both := multiResolver{ts1.keys, ts2.keys}
	got, err := scitt.VerifyTransparent(ctx, data, issuer.keys, both, 2)
	if err != nil {
		t.Fatalf("VerifyTransparent: %v", err)
	}
	if got.Claims.Issuer != "https://issuer.example" || got.Claims.Subject != "pkg:example/widget@1.0" {
		t.Errorf("claims = %+v", got.Claims)
	}
	if got.Type != "application/example+cose" {
		t.Errorf("typ = %v", got.Type)
	}

	// Only one service trusted: 1 of 2 verifies.
	if _, err := scitt.VerifyTransparent(ctx, data, issuer.keys, ts1.keys, 1); err != nil {
		t.Errorf("one trusted service, min 1: %v", err)
	}
	if _, err := scitt.VerifyTransparent(ctx, data, issuer.keys, ts1.keys, 2); !errors.Is(err, scitt.ErrInsufficientReceipts) || !errors.Is(err, cose.ErrVerification) {
		t.Errorf("one trusted service, min 2: err = %v, want ErrInsufficientReceipts", err)
	}
	// Wrong issuer key.
	other := newParty(t, "issuer-1")
	if _, err := scitt.VerifyTransparent(ctx, data, other.keys, both, 1); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("wrong issuer key: err = %v, want ErrVerification", err)
	}
	// Receipts only.
	if _, err := scitt.Verify(ctx, data, scitt.VerifyOptions{SkipIssuerSignature: true, ServiceKeys: both}); err != nil {
		t.Errorf("SkipIssuerSignature: %v", err)
	}
	// No receipts at all.
	plain, err := scitt.Issue(ctx, issuer.signer, []byte("x"), scitt.IssueOptions{Issuer: "i", Subject: "s", KeyID: issuer.kid})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, plain.Msg), issuer.keys, both, 1); !errors.Is(err, scitt.ErrInsufficientReceipts) {
		t.Errorf("no receipts: err = %v, want ErrInsufficientReceipts", err)
	}
	// A receipt for a different statement doesn't count.
	r := ts1.register(t, plain, true)
	if err := receipt.Attach(plain.Msg, r); err != nil {
		t.Fatal(err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, plain.Msg), issuer.keys, both, 1); err != nil {
		t.Errorf("own receipt: %v", err)
	}
	if err := receipt.Attach(st.Msg, r); err != nil {
		t.Fatal(err)
	}
	if _, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, both, 3); !errors.Is(err, scitt.ErrInsufficientReceipts) {
		t.Errorf("foreign receipt: err = %v, want ErrInsufficientReceipts", err)
	}
	// Missing service keys.
	if _, err := scitt.Verify(ctx, data, scitt.VerifyOptions{IssuerKeys: issuer.keys}); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("no service keys: err = %v", err)
	}
}

// multiResolver tries each resolver in turn.
type multiResolver []cose.KeyResolver

func (m multiResolver) ResolveKey(ctx context.Context, protected, unprotected *cose.Headers) ([]*cose.Key, error) {
	var out []*cose.Key
	for _, r := range m {
		ks, err := r.ResolveKey(ctx, protected, unprotected)
		if err == nil {
			out = append(out, ks...)
		}
	}
	return out, nil
}

// TestReceiptClaimsRequired: RFC 9943 §6 requires CWT Claims in a
// receipt's protected header.
func TestReceiptClaimsRequired(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	st, err := scitt.Issue(ctx, issuer.signer, []byte("x"), scitt.IssueOptions{Issuer: "i", Subject: "s", KeyID: issuer.kid})
	if err != nil {
		t.Fatal(err)
	}
	ts := newService(t, "ts.example", 3)
	if err := receipt.Attach(st.Msg, ts.register(t, st, false)); err != nil {
		t.Fatal(err)
	}
	_, err = scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, ts.keys, 1)
	if !errors.Is(err, scitt.ErrInsufficientReceipts) || !errors.Is(err, scitt.ErrInvalidStatement) {
		t.Fatalf("receipt without claims: err = %v", err)
	}
	if _, err := scitt.ReceiptHeaders("", "s"); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("ReceiptHeaders without iss: err = %v", err)
	}
}

// TestStatementClaimsBucket: CWT Claims must be protected, with iss and
// sub; kid is required unless x5t/x5chain is protected.
func TestStatementClaimsBucket(t *testing.T) {
	ctx := context.Background()
	p := newParty(t, "k")
	sign := func(t *testing.T, build func(m *cose.Sign1)) []byte {
		t.Helper()
		m := &cose.Sign1{Payload: []byte("x")}
		build(m)
		if err := p.signer.Sign1Context(ctx, m); err != nil {
			t.Fatal(err)
		}
		return marshal(t, m)
	}
	claims := func(iss, sub string) *cwt.ClaimsSet { return &cwt.ClaimsSet{Issuer: iss, Subject: sub} }
	set := func(t *testing.T, h *cose.Headers, c *cwt.ClaimsSet) {
		t.Helper()
		if err := cwt.SetClaimsHeader(h, c); err != nil {
			t.Fatal(err)
		}
	}
	cert := []byte{0x30, 0x03, 0x02, 0x01, 0x01} // shape only; not parsed
	cases := map[string]func(m *cose.Sign1){
		"claims-unprotected": func(m *cose.Sign1) {
			m.Protected.SetKeyID(p.kid)
			set(t, &m.Unprotected, claims("i", "s"))
		},
		"no-claims": func(m *cose.Sign1) { m.Protected.SetKeyID(p.kid) },
		"no-iss":    func(m *cose.Sign1) { m.Protected.SetKeyID(p.kid); set(t, &m.Protected, claims("", "s")) },
		"no-sub":    func(m *cose.Sign1) { m.Protected.SetKeyID(p.kid); set(t, &m.Protected, claims("i", "")) },
		"no-kid":    func(m *cose.Sign1) { set(t, &m.Protected, claims("i", "s")) },
		"kid-unprotected": func(m *cose.Sign1) {
			m.Unprotected.SetKeyID(p.kid)
			set(t, &m.Protected, claims("i", "s"))
		},
		"x5chain-unprotected": func(m *cose.Sign1) {
			if err := m.Unprotected.SetX5Chain(cert); err != nil {
				t.Fatal(err)
			}
			set(t, &m.Protected, claims("https://i.example", "s"))
		},
		"x5-iss-not-uri": func(m *cose.Sign1) {
			if err := m.Protected.SetX5Chain(cert); err != nil {
				t.Fatal(err)
			}
			set(t, &m.Protected, claims("not a uri: really", "s"))
		},
		"x5-iss-too-long": func(m *cose.Sign1) {
			if err := m.Protected.SetX5T(cose.AlgSHA256, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
			set(t, &m.Protected, claims("https://i.example/"+strings.Repeat("a", scitt.MaxIssuerLength), "s"))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := scitt.ParseStatement(sign(t, build))
			if !errors.Is(err, scitt.ErrInvalidStatement) || !errors.Is(err, cose.ErrMalformed) {
				t.Fatalf("err = %v, want ErrInvalidStatement", err)
			}
		})
	}

	ok := map[string]func(m *cose.Sign1){
		"kid": func(m *cose.Sign1) { m.Protected.SetKeyID(p.kid); set(t, &m.Protected, claims("i", "s")) },
		"x5chain-no-kid": func(m *cose.Sign1) {
			if err := m.Protected.SetX5Chain(cert); err != nil {
				t.Fatal(err)
			}
			set(t, &m.Protected, claims("https://i.example", "s"))
		},
		"x5t-no-kid-plain-iss": func(m *cose.Sign1) {
			if err := m.Protected.SetX5T(cose.AlgSHA256, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
			set(t, &m.Protected, claims("issuer-without-colon", "s"))
		},
	}
	for name, build := range ok {
		t.Run(name, func(t *testing.T) {
			if _, err := scitt.ParseStatement(sign(t, build)); err != nil {
				t.Fatal(err)
			}
		})
	}

	// Untagged COSE_Sign1 is rejected.
	m := &cose.Sign1{Payload: []byte("x")}
	m.Protected.SetKeyID(p.kid)
	set(t, &m.Protected, claims("i", "s"))
	if err := p.signer.Sign1Context(ctx, m); err != nil {
		t.Fatal(err)
	}
	tagged := marshal(t, m)
	if _, err := scitt.ParseStatement(tagged[1:]); !errors.Is(err, scitt.ErrInvalidStatement) {
		t.Errorf("untagged: err = %v", err)
	}
	if _, err := scitt.ParseStatement(append([]byte{0xd9, 0xd9, 0xf7}, tagged...)); err != nil {
		t.Errorf("self-described: %v", err)
	}
}

func TestIssueRejects(t *testing.T) {
	ctx := context.Background()
	p := newParty(t, "k")
	env := &cose.HashEnvelope{HashAlg: cose.AlgSHA256}
	cases := map[string]scitt.IssueOptions{
		"no-iss":              {Subject: "s", KeyID: p.kid},
		"no-sub":              {Issuer: "i", KeyID: p.kid},
		"no-kid":              {Issuer: "i", Subject: "s"},
		"envelope-and-ctype":  {Issuer: "i", Subject: "s", KeyID: p.kid, HashEnvelope: env, ContentType: "text/plain"},
		"x5-iss-colon-no-uri": {Issuer: ":bad", Subject: "s", X5T: &cose.CertHash{Alg: cose.AlgSHA256, Hash: make([]byte, 32)}},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := scitt.Issue(ctx, p.signer, []byte("x"), o); !errors.Is(err, cose.ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	// Claims are merged, not modified.
	c := &cwt.ClaimsSet{Issuer: "old", Audience: "aud"}
	st, err := scitt.Issue(ctx, p.signer, []byte("x"), scitt.IssueOptions{Issuer: "i", Subject: "s", KeyID: p.kid, Claims: c})
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "old" || st.Claims.Issuer != "i" || st.Claims.Audience != "aud" {
		t.Errorf("claims merge: input %+v, statement %+v", c, st.Claims)
	}
	// A kid set on the Signer satisfies the rule.
	var prot cose.Headers
	prot.SetKeyID([]byte("signer-kid"))
	ps := newParty(t, "signer-kid", cose.WithProtectedHeaders(prot))
	if _, err := scitt.Issue(ctx, ps.signer, []byte("x"), scitt.IssueOptions{Issuer: "i", Subject: "s"}); err != nil {
		t.Errorf("signer kid: %v", err)
	}
}

// TestHashEnvelopeStatement: RFC 9943 §6.2 statements signing a digest,
// attached and detached, with receipts.
func TestHashEnvelopeStatement(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	ts := newService(t, "ts.example", 7)
	artifact := []byte("a large release artifact")
	digest := sha256.Sum256(artifact)
	env := &cose.HashEnvelope{HashAlg: cose.AlgSHA256, PreimageContentType: "application/octet-stream", Location: "https://dl.example/a.bin"}
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached=%v", detached), func(t *testing.T) {
			st, err := scitt.Issue(ctx, issuer.signer, artifact, scitt.IssueOptions{
				Issuer: "https://issuer.example", Subject: "a.bin", KeyID: issuer.kid,
				HashEnvelope: env, Detached: detached,
			})
			if err != nil {
				t.Fatal(err)
			}
			if st.HashEnvelope == nil || *st.HashEnvelope != *env {
				t.Fatalf("envelope = %+v", st.HashEnvelope)
			}
			if err := receipt.Attach(st.Msg, ts.register(t, st, true)); err != nil {
				t.Fatal(err)
			}
			data := marshal(t, st.Msg)
			o := scitt.VerifyOptions{IssuerKeys: issuer.keys, ServiceKeys: ts.keys}
			if detached {
				if _, err := scitt.Verify(ctx, data, o); !errors.Is(err, cose.ErrMissingPayload) {
					t.Errorf("detached, no digest: err = %v, want ErrMissingPayload", err)
				}
				o.Payload = digest[:]
			}
			if _, err := scitt.Verify(ctx, data, o); err != nil {
				t.Fatalf("digest: %v", err)
			}
			o.Payload, o.Preimage = nil, artifact
			if _, err := scitt.Verify(ctx, data, o); err != nil {
				t.Fatalf("preimage: %v", err)
			}
			o.Preimage = []byte("tampered")
			if _, err := scitt.Verify(ctx, data, o); !errors.Is(err, cose.ErrVerification) {
				t.Fatalf("wrong preimage: err = %v, want ErrVerification", err)
			}
		})
	}
}

// TestDetachedStatement verifies a detached (non-envelope) statement.
func TestDetachedStatement(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	ts := newService(t, "ts.example", 2)
	st, err := scitt.Issue(ctx, issuer.signer, []byte("payload"), scitt.IssueOptions{Issuer: "i", Subject: "s", KeyID: issuer.kid, Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Msg.Payload != nil {
		t.Fatal("payload attached")
	}
	if err := receipt.Attach(st.Msg, ts.register(t, st, true)); err != nil {
		t.Fatal(err)
	}
	data := marshal(t, st.Msg)
	o := scitt.VerifyOptions{IssuerKeys: issuer.keys, ServiceKeys: ts.keys}
	if _, err := scitt.Verify(ctx, data, o); !errors.Is(err, cose.ErrMissingPayload) {
		t.Errorf("no payload: err = %v", err)
	}
	o.Payload = []byte("payload")
	if _, err := scitt.Verify(ctx, data, o); err != nil {
		t.Fatal(err)
	}
	o.Payload = []byte("other")
	if _, err := scitt.Verify(ctx, data, o); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("wrong payload: err = %v", err)
	}
}

// TestEntry: the registered entry has an empty unprotected bucket and
// is unchanged by attaching receipts.
func TestEntry(t *testing.T) {
	ctx := context.Background()
	issuer := newParty(t, "issuer-1")
	st, err := scitt.Issue(ctx, issuer.signer, []byte("x"), scitt.IssueOptions{Issuer: "i", Subject: "s", KeyID: issuer.kid})
	if err != nil {
		t.Fatal(err)
	}
	before, err := scitt.Entry(st.Msg)
	if err != nil {
		t.Fatal(err)
	}
	ts := newService(t, "ts.example", 1)
	if err := receipt.Attach(st.Msg, ts.register(t, st, true)); err != nil {
		t.Fatal(err)
	}
	after, err := scitt.Entry(st.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Entry changed after Attach")
	}
	if st.Msg.Unprotected.IsEmpty() {
		t.Fatal("Entry modified the statement")
	}
	m, err := cose.UnmarshalSign1(after)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Unprotected.IsEmpty() {
		t.Error("entry unprotected bucket not empty")
	}
}

// TestSignedStatementAlgorithmEmission: polymorphic and RFC 9864
// fully-specified issuer algorithms both verify end to end.
func TestSignedStatementAlgorithmEmission(t *testing.T) {
	ctx := context.Background()
	for name, opts := range map[string][]cose.SignerOption{
		"polymorphic":     nil,
		"fully-specified": {cose.WithFullySpecifiedAlgorithms()},
	} {
		t.Run(name, func(t *testing.T) {
			issuer := newParty(t, "issuer-1", opts...)
			st, err := scitt.Issue(ctx, issuer.signer, []byte("x"), scitt.IssueOptions{Issuer: "i", Subject: "s", KeyID: issuer.kid})
			if err != nil {
				t.Fatal(err)
			}
			want := cose.Algorithm(-7) // ES256, NewSigner's polymorphic default
			if opts != nil {
				want = cose.AlgESP256
			}
			if got := st.Msg.Protected.Algorithm(); got != want {
				t.Errorf("alg = %v, want %v", got, want)
			}
			ts := newService(t, "ts.example", 4)
			if err := receipt.Attach(st.Msg, ts.register(t, st, true)); err != nil {
				t.Fatal(err)
			}
			if _, err := scitt.VerifyTransparent(ctx, marshal(t, st.Msg), issuer.keys, ts.keys, 1); err != nil {
				t.Fatal(err)
			}
		})
	}
}
