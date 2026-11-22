// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package receipt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
)

type logFixture struct {
	tree    receipt.Tree
	entries [][]byte
	signer  *cose.Signer
	keys    cose.KeyResolver
}

func newLog(t testing.TB, n int, opts ...cose.SignerOption) *logFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var prot cose.Headers
	prot.SetKeyID([]byte("ts-key-1"))
	s, err := cose.NewSigner(priv, append([]cose.SignerOption{cose.WithProtectedHeaders(prot)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cose.NewKeyFromPublic(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.SetID([]byte("ts-key-1"))
	l := &logFixture{signer: s, keys: cose.KeySetResolver(cose.KeySet{k})}
	for i := range n {
		e := []byte(fmt.Sprintf("entry-%d", i))
		l.entries = append(l.entries, e)
		l.tree.Append(e)
	}
	return l
}

func (l *logFixture) inclusion(t testing.TB, index, size uint64) *receipt.Receipt {
	t.Helper()
	p, err := l.tree.InclusionProof(index, size)
	if err != nil {
		t.Fatal(err)
	}
	root, err := l.tree.Root(size)
	if err != nil {
		t.Fatal(err)
	}
	r, err := receipt.Issue(context.Background(), l.signer, root, p, cose.Headers{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestReceiptRFC9942Example rebuilds the RFC 9942 Figure 6 receipt of
// inclusion (tree size 20, leaf 17, three path hashes, ES256, detached
// payload; the RFC elides the hashes and signature) and checks its
// encoding and verification.
func TestReceiptRFC9942Example(t *testing.T) {
	l := newLog(t, 20)
	r := l.inclusion(t, 17, 20)
	wire, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	v, err := corecbor.NewDecoder().Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != corecbor.KindTag || v.TagID() != 18 {
		t.Fatalf("receipt is not tag 18: %s", corecbor.DiagnosticValue(v))
	}
	arr := v.TagInner().Array()
	prot, err := corecbor.NewDecoder().Decode(arr[0].BytesVal())
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := prot.GetInt(1); a.Kind != corecbor.KindNegInt || a.NegIntVal() != 6 {
		t.Errorf("protected alg = %s, want -7 (ES256)", corecbor.DiagnosticValue(a))
	}
	if vds, _ := prot.GetInt(395); vds.Kind != corecbor.KindUint || vds.UintVal() != 1 {
		t.Errorf("protected vds = %s, want 1", corecbor.DiagnosticValue(vds))
	}
	if arr[2].Kind != corecbor.KindNull {
		t.Errorf("payload = %s, want null (detached)", corecbor.DiagnosticValue(arr[2]))
	}
	vdp, ok := arr[1].GetInt(396)
	if !ok {
		t.Fatal("unprotected vdp (396) missing")
	}
	incl, ok := vdp.GetInt(-1)
	if !ok || len(incl.Array()) != 1 || incl.Array()[0].Kind != corecbor.KindBytes {
		t.Fatalf("vdp -1 = %s, want [bstr]", corecbor.DiagnosticValue(incl))
	}
	proof, err := corecbor.NewDecoder().Decode(incl.Array()[0].BytesVal())
	if err != nil {
		t.Fatal(err)
	}
	pa := proof.Array()
	if len(pa) != 3 || pa[0].UintVal() != 20 || pa[1].UintVal() != 17 || len(pa[2].Array()) != 3 {
		t.Fatalf("inclusion proof = %s, want [20, 17, [3 hashes]]", corecbor.DiagnosticValue(proof))
	}

	parsed, err := receipt.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := parsed.VerifyInclusion(ctx, l.entries[17], l.keys); err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if err := parsed.VerifyInclusion(ctx, l.entries[16], l.keys); !errors.Is(err, cose.ErrVerification) {
		t.Errorf("wrong entry: err = %v, want ErrVerification", err)
	}
}

// TestReceiptRFC9943ProofBytes checks the encoded inclusion proof
// against the bytes RFC 9943 Figure 9 shows for tree size 8, leaf 7:
// h'83080783...' ([8, 7, [3 hashes]]).
func TestReceiptRFC9943ProofBytes(t *testing.T) {
	l := newLog(t, 8)
	r := l.inclusion(t, 7, 8)
	wire, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	v, err := corecbor.NewDecoder().Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	vdp, _ := v.TagInner().Array()[1].GetInt(396)
	incl, _ := vdp.GetInt(-1)
	b := incl.Array()[0].BytesVal()
	if want := "83080783"; !bytes.HasPrefix(b, mustHex(t, want)) {
		t.Fatalf("proof bytes %x, want prefix %s", b[:4], want)
	}
	if len(b) != 4+3*34 {
		t.Fatalf("proof is %d bytes, want %d", len(b), 4+3*34)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReceiptsAttached rebuilds RFC 9942 Figure 2: a signed statement
// with two receipts (tree 9 leaf 8, tree 6 leaf 5) in label 394.
func TestReceiptsAttached(t *testing.T) {
	ctx := context.Background()
	l := newLog(t, 9)
	entry := l.entries[8]

	stmtKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := cose.NewSigner(stmtKey)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := ss.Sign(entry)
	if err != nil {
		t.Fatal(err)
	}
	r1 := l.inclusion(t, 8, 9)

	l2 := newLog(t, 6)
	l2.entries[5] = entry
	var t2 receipt.Tree
	for _, e := range l2.entries {
		t2.Append(e)
	}
	l2.tree = t2
	r2 := l2.inclusion(t, 5, 6)

	if err := receipt.Attach(stmt, r1); err != nil {
		t.Fatal(err)
	}
	wire, err := cose.MarshalSign1(stmt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cose.UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	// Attach to a decoded statement (label 394 decoded as an array).
	if err := receipt.Attach(decoded, r2); err != nil {
		t.Fatal(err)
	}
	wire, err = cose.MarshalSign1(decoded)
	if err != nil {
		t.Fatal(err)
	}
	final, err := cose.UnmarshalSign1(wire)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := receipt.Receipts(final)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("got %d receipts, want 2", len(rs))
	}
	if err := rs[0].VerifyInclusion(ctx, entry, l.keys); err != nil {
		t.Errorf("receipt 1: %v", err)
	}
	if err := rs[1].VerifyInclusion(ctx, entry, l2.keys); err != nil {
		t.Errorf("receipt 2: %v", err)
	}
	// Attaching receipts doesn't touch the statement's signature.
	v, err := cose.NewVerifier(&stmtKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(final); err != nil {
		t.Errorf("statement signature after Attach: %v", err)
	}
}

// TestReceiptConsistency rebuilds the RFC 9942 Figure 9 setting: a
// consistency receipt from size 20 to 104, checked against an older
// inclusion receipt at size 20.
func TestReceiptConsistency(t *testing.T) {
	ctx := context.Background()
	l := newLog(t, 104)
	older := l.inclusion(t, 17, 20)
	cp, err := l.tree.ConsistencyProof(20, 104)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Path) != 6 {
		t.Fatalf("consistency path has %d entries, want 6 (RFC 9942 Figure 9)", len(cp.Path))
	}
	newRoot, _ := l.tree.Root(104)
	newer, err := receipt.IssueConsistency(ctx, l.signer, newRoot, cp, cose.Headers{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := newer.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	newer, err = receipt.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyConsistency(ctx, older, l.entries[17], newer, l.keys); err != nil {
		t.Fatalf("VerifyConsistency: %v", err)
	}
	oldRoot, _ := l.tree.Root(20)
	got, err := newer.VerifyConsistencyFrom(ctx, oldRoot, l.keys)
	if err != nil || !bytes.Equal(got, newRoot) {
		t.Fatalf("VerifyConsistencyFrom: root %x err %v", got, err)
	}
	other, _ := l.tree.Root(19)
	if _, err := newer.VerifyConsistencyFrom(ctx, other, l.keys); !errors.Is(err, receipt.ErrProof) || !errors.Is(err, cose.ErrVerification) {
		t.Errorf("wrong old root: err = %v, want ErrProof (wrapping ErrVerification)", err)
	}
	// An older receipt for a different size doesn't chain.
	olderAt21 := l.inclusion(t, 17, 21)
	if err := receipt.VerifyConsistency(ctx, olderAt21, l.entries[17], newer, l.keys); !errors.Is(err, receipt.ErrProof) {
		t.Errorf("size mismatch: err = %v, want ErrProof", err)
	}
	// Mixing receipt kinds is rejected.
	if _, err := older.VerifyConsistencyFrom(ctx, oldRoot, l.keys); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("consistency on an inclusion receipt: err = %v, want ErrMalformed", err)
	}
	if err := newer.VerifyInclusion(ctx, l.entries[0], l.keys); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("inclusion on a consistency receipt: err = %v, want ErrMalformed", err)
	}
}

// rawSign1 encodes a COSE_Sign1 by hand so shape tests can build
// receipts a Signer won't produce. The signature is a placeholder:
// Parse checks shape, not signatures.
func rawSign1(t *testing.T, tagged bool, prot, unprot corecbor.Value, payload corecbor.Value) []byte {
	t.Helper()
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	pb, err := enc.Encode(nil, prot)
	if err != nil {
		t.Fatal(err)
	}
	arr := corecbor.MakeArray(corecbor.Bytes(pb), unprot, payload, corecbor.Bytes(make([]byte, 64)))
	v := arr
	if tagged {
		v = corecbor.MakeTag(18, arr)
	}
	b, err := enc.Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func intKey(n int64) corecbor.Value {
	if n < 0 {
		return corecbor.NegInt(uint64(-1 - n))
	}
	return corecbor.Uint(uint64(n))
}

func cmap(kv ...any) corecbor.Value {
	var pairs []corecbor.MapEntry
	for i := 0; i < len(kv); i += 2 {
		pairs = append(pairs, corecbor.MapEntry{Key: intKey(kv[i].(int64)), Value: kv[i+1].(corecbor.Value)})
	}
	return corecbor.MakeMap(pairs...)
}

func proofBstr(t *testing.T, a, b uint64, path ...[]byte) corecbor.Value {
	t.Helper()
	items := make([]corecbor.Value, len(path))
	for i, p := range path {
		items[i] = corecbor.Bytes(p)
	}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	out, err := enc.Encode(nil, corecbor.MakeArray(corecbor.Uint(a), corecbor.Uint(b), corecbor.MakeArrayFromSlice(items)))
	if err != nil {
		t.Fatal(err)
	}
	return corecbor.Bytes(out)
}

func TestReceiptShape(t *testing.T) {
	h := make([]byte, 32)
	alg := cmap(int64(1), intKey(-7), int64(395), corecbor.Uint(1))
	goodVDP := cmap(int64(396), cmap(int64(-1), corecbor.MakeArray(proofBstr(t, 2, 1, h))))
	null := corecbor.Null()
	cases := []struct {
		name   string
		data   []byte
		target error
	}{
		{"untagged", rawSign1(t, false, alg, goodVDP, null), cose.ErrMalformed},
		{"attached-payload", rawSign1(t, true, alg, goodVDP, corecbor.Bytes(h)), cose.ErrMalformed},
		{"vds-missing", rawSign1(t, true, cmap(int64(1), intKey(-7)), goodVDP, null), cose.ErrMalformed},
		{"vds-unprotected", rawSign1(t, true, cmap(int64(1), intKey(-7)), cmap(int64(395), corecbor.Uint(1), int64(396), cmap(int64(-1), corecbor.MakeArray(proofBstr(t, 2, 1, h)))), null), cose.ErrMalformed},
		{"vds-unknown", rawSign1(t, true, cmap(int64(1), intKey(-7), int64(395), corecbor.Uint(2)), goodVDP, null), cose.ErrUnsupportedAlgorithm},
		{"vdp-protected", rawSign1(t, true, cmap(int64(1), intKey(-7), int64(395), corecbor.Uint(1), int64(396), cmap(int64(-1), corecbor.MakeArray(proofBstr(t, 2, 1, h)))), cmap(), null), cose.ErrMalformed},
		{"vdp-missing", rawSign1(t, true, alg, cmap(), null), cose.ErrMalformed},
		{"vdp-not-map", rawSign1(t, true, alg, cmap(int64(396), corecbor.MakeArray()), null), cose.ErrMalformed},
		{"proof-type-unknown", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-3), corecbor.MakeArray(proofBstr(t, 2, 1, h)))), null), cose.ErrMalformed},
		{"proofs-empty", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-1), corecbor.MakeArray())), null), cose.ErrMalformed},
		{"proof-not-bstr", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-1), corecbor.MakeArray(corecbor.Uint(1)))), null), cose.ErrMalformed},
		{"proof-arity", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-1), corecbor.MakeArray(corecbor.Bytes([]byte{0x82, 0x02, 0x01})))), null), cose.ErrMalformed},
		{"node-33-bytes", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-1), corecbor.MakeArray(proofBstr(t, 2, 1, make([]byte, 33))))), null), cose.ErrMalformed},
		{"index-equals-size", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-1), corecbor.MakeArray(proofBstr(t, 2, 2, h)))), null), cose.ErrMalformed},
		{"short-path", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-1), corecbor.MakeArray(proofBstr(t, 4, 1, h)))), null), cose.ErrMalformed},
		{"both-kinds", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-1), corecbor.MakeArray(proofBstr(t, 2, 1, h)), int64(-2), corecbor.MakeArray(proofBstr(t, 1, 2, h)))), null), cose.ErrMalformed},
		{"consistency-equal-sizes", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-2), corecbor.MakeArray(proofBstr(t, 2, 2, h)))), null), cose.ErrMalformed},
		{"consistency-empty-path", rawSign1(t, true, alg, cmap(int64(396), cmap(int64(-2), corecbor.MakeArray(proofBstr(t, 1, 2)))), null), cose.ErrMalformed},
		{"truncated", []byte{0xd2, 0x84}, cose.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := receipt.Parse(c.data)
			if !errors.Is(err, c.target) {
				t.Fatalf("err = %v, want %v", err, c.target)
			}
		})
	}
	// The well-formed baseline parses.
	if _, err := receipt.Parse(rawSign1(t, true, alg, goodVDP, null)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	// A leading self-describe tag is accepted, as the decoder strips it.
	sd := append([]byte{0xd9, 0xd9, 0xf7}, rawSign1(t, true, alg, goodVDP, null)...)
	if _, err := receipt.Parse(sd); err != nil {
		t.Fatalf("self-described: %v", err)
	}
}

// TestReceiptMultipleInclusionProofs checks the single-result rule: a
// receipt verifies only if every inclusion proof yields the signed root.
func TestReceiptMultipleInclusionProofs(t *testing.T) {
	ctx := context.Background()
	l := newLog(t, 8)
	root, _ := l.tree.Root(8)
	p, _ := l.tree.InclusionProof(3, 8)
	sign := func(t *testing.T, proofs ...receipt.InclusionProof) []byte {
		t.Helper()
		items := make([]corecbor.Value, len(proofs))
		for i, q := range proofs {
			items[i] = proofBstr(t, q.TreeSize, q.LeafIndex, q.Path...)
		}
		msg := &cose.Sign1{Payload: root}
		if err := msg.Protected.SetChecked(receipt.HeaderVDS, int64(1)); err != nil {
			t.Fatal(err)
		}
		if err := msg.Unprotected.SetChecked(receipt.HeaderVDP, cmap(int64(-1), corecbor.MakeArrayFromSlice(items))); err != nil {
			t.Fatal(err)
		}
		if err := l.signer.Sign1(msg); err != nil {
			t.Fatal(err)
		}
		msg.Payload = nil
		b, err := cose.MarshalSign1(msg)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r, err := receipt.Parse(sign(t, p, p))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.VerifyInclusion(ctx, l.entries[3], l.keys); err != nil {
		t.Errorf("two agreeing proofs: %v", err)
	}
	other, _ := l.tree.InclusionProof(4, 8)
	r, err = receipt.Parse(sign(t, p, other))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.VerifyInclusion(ctx, l.entries[3], l.keys); !errors.Is(err, receipt.ErrProof) {
		t.Errorf("disagreeing proofs: err = %v, want ErrProof", err)
	}
}

func TestIssueRejects(t *testing.T) {
	ctx := context.Background()
	l := newLog(t, 4)
	root, _ := l.tree.Root(4)
	good, _ := l.tree.InclusionProof(1, 4)
	if _, err := receipt.Issue(ctx, l.signer, root[:31], good, cose.Headers{}); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("short root: err = %v", err)
	}
	bad := good
	bad.LeafIndex = 4
	if _, err := receipt.Issue(ctx, l.signer, root, bad, cose.Headers{}); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("index >= size: err = %v", err)
	}
	var vds2 cose.Headers
	if err := vds2.SetChecked(receipt.HeaderVDS, int64(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.Issue(ctx, l.signer, root, good, vds2); !errors.Is(err, cose.ErrUnsupportedAlgorithm) {
		t.Errorf("vds 2: err = %v", err)
	}
	if _, err := receipt.IssueConsistency(ctx, l.signer, root, receipt.ConsistencyProof{TreeSize1: 4, TreeSize2: 4}, cose.Headers{}); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("equal sizes: err = %v", err)
	}
}

// TestReceiptAlgorithmEmission issues receipts with polymorphic and
// RFC 9864 fully-specified algorithms; both verify.
func TestReceiptAlgorithmEmission(t *testing.T) {
	for name, opts := range map[string][]cose.SignerOption{
		"polymorphic":     nil,
		"fully-specified": {cose.WithFullySpecifiedAlgorithms()},
	} {
		t.Run(name, func(t *testing.T) {
			l := newLog(t, 5, opts...)
			r := l.inclusion(t, 2, 5)
			want := cose.Algorithm(-7) // ES256, NewSigner's polymorphic default
			if opts != nil {
				want = cose.AlgESP256
			}
			if got := r.Msg.Protected.Algorithm(); got != want {
				t.Errorf("alg = %v, want %v", got, want)
			}
			if err := r.VerifyInclusion(context.Background(), l.entries[2], l.keys); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkVerifyInclusionMerkle(b *testing.B) {
	// Tree of 2^20 leaves: a synthetic path of 20 hashes (building the
	// tree itself would dominate), root computed once.
	const size = 1 << 20
	index := uint64(size - 12345)
	path := make([][]byte, 20)
	for i := range path {
		path[i] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	r := &receipt.Receipt{Inclusion: []receipt.InclusionProof{{TreeSize: size, LeafIndex: index, Path: path}}}
	leaf := receipt.LeafHash([]byte("entry"))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.InclusionRoot(leaf); err != nil {
			b.Fatal(err)
		}
	}
}
