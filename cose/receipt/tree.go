// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package receipt

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt/internal/merkle"
)

// Tree is an in-memory RFC 9162 SHA-256 Merkle Tree that produces roots
// and proofs for Issue and IssueConsistency. It recomputes subtree
// hashes on demand, so it suits tests and small logs, not production
// transparency services.
//
// Experimental: may change or move.
type Tree struct {
	t merkle.Tree
}

// Append adds entry as the next leaf and returns its index.
func (t *Tree) Append(entry []byte) uint64 { return t.t.Append(entry) }

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return t.t.Size() }

// Root returns the Merkle Tree root of the first size leaves.
func (t *Tree) Root(size uint64) ([]byte, error) {
	r, err := t.t.Root(size)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", cose.ErrMalformed, err)
	}
	return r, nil
}

// InclusionProof returns the inclusion proof for leaf index in the tree
// of the first size leaves.
func (t *Tree) InclusionProof(index, size uint64) (InclusionProof, error) {
	p, err := t.t.InclusionProof(index, size)
	if err != nil {
		return InclusionProof{}, fmt.Errorf("%w: %w", cose.ErrMalformed, err)
	}
	return InclusionProof{TreeSize: size, LeafIndex: index, Path: p}, nil
}

// ConsistencyProof returns the consistency proof from the tree of the
// first size1 leaves to the tree of the first size2 leaves
// (0 < size1 < size2 <= Size()).
func (t *Tree) ConsistencyProof(size1, size2 uint64) (ConsistencyProof, error) {
	p, err := t.t.ConsistencyProof(size1, size2)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("%w: %w", cose.ErrMalformed, err)
	}
	return ConsistencyProof{TreeSize1: size1, TreeSize2: size2, Path: p}, nil
}
