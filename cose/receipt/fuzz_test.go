// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package receipt_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
)

// FuzzReceiptParse: Parse never panics, and a receipt it accepts
// re-encodes to bytes that parse to the same proofs.
func FuzzReceiptParse(f *testing.F) {
	l := newLog(f, 20)
	for _, ip := range [][2]uint64{{17, 20}, {0, 1}, {8, 9}} {
		r := l.inclusion(f, ip[0], ip[1])
		b, err := r.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	cp, err := l.tree.ConsistencyProof(5, 20)
	if err != nil {
		f.Fatal(err)
	}
	root, _ := l.tree.Root(20)
	cr, err := receipt.IssueConsistency(context.Background(), l.signer, root, cp, cose.Headers{})
	if err != nil {
		f.Fatal(err)
	}
	b, err := cr.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte{0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := receipt.Parse(data)
		if err != nil {
			if !errors.Is(err, cose.ErrMalformed) && !errors.Is(err, cose.ErrUnsupportedAlgorithm) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		out, err := r.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a parsed receipt: %v", err)
		}
		again, err := receipt.Parse(out)
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if len(again.Inclusion) != len(r.Inclusion) || len(again.Consistency) != len(r.Consistency) {
			t.Fatal("proof count changed across re-encode")
		}
	})
}

func splitPath(b []byte) [][]byte {
	var path [][]byte
	for len(b) >= 32 {
		path = append(path, b[:32])
		b = b[32:]
	}
	if len(b) > 0 {
		path = append(path, b) // a malformed tail element
	}
	return path
}

// FuzzInclusionVerify: computing an inclusion root never panics, and a
// root it computes is stable for the same input.
func FuzzInclusionVerify(f *testing.F) {
	l := newLog(f, 9)
	p, _ := l.tree.InclusionProof(5, 9)
	f.Add(uint64(5), uint64(9), l.entries[5], bytes.Join(p.Path, nil))
	f.Add(uint64(0), uint64(1), []byte("x"), []byte{})
	f.Add(uint64(1<<63), uint64(1<<63), []byte{}, make([]byte, 33))
	f.Fuzz(func(t *testing.T, index, size uint64, entry, pathBytes []byte) {
		path := splitPath(pathBytes)
		r := &receipt.Receipt{Inclusion: []receipt.InclusionProof{{TreeSize: size, LeafIndex: index, Path: path}}}
		root, err := r.InclusionRoot(receipt.LeafHash(entry))
		if err != nil {
			if !errors.Is(err, receipt.ErrProof) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		again, err := r.InclusionRoot(receipt.LeafHash(entry))
		if err != nil || !bytes.Equal(root, again) {
			t.Fatal("inclusion root not deterministic")
		}
	})
}

// FuzzConsistencyVerify: applying a consistency proof never panics.
func FuzzConsistencyVerify(f *testing.F) {
	l := newLog(f, 20)
	cp, _ := l.tree.ConsistencyProof(5, 20)
	old, _ := l.tree.Root(5)
	f.Add(uint64(5), uint64(20), old, bytes.Join(cp.Path, nil))
	f.Add(uint64(1), uint64(1), old, []byte{})
	f.Fuzz(func(t *testing.T, size1, size2 uint64, oldRoot, pathBytes []byte) {
		r := &receipt.Receipt{
			Msg:         &cose.Sign1{},
			Consistency: []receipt.ConsistencyProof{{TreeSize1: size1, TreeSize2: size2, Path: splitPath(pathBytes)}},
		}
		// No keys resolve, so a proof that holds still fails at the
		// signature; either way the result is an error, never a panic.
		none := cose.KeyResolverFunc(func(context.Context, *cose.Headers, *cose.Headers) ([]*cose.Key, error) { return nil, nil })
		if _, err := r.VerifyConsistencyFrom(context.Background(), oldRoot, none); !errors.Is(err, cose.ErrVerification) {
			t.Fatalf("err = %v, want ErrVerification", err)
		}
	})
}
