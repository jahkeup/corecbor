// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package merkle implements the RFC 9162 §2.1 Merkle Tree with SHA-256:
// the Merkle Tree Hash, inclusion proof verification (§2.1.3.2) and
// consistency proof verification (§2.1.4.2), plus proof generation for
// an in-memory tree.
package merkle

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/bits"
)

// HashSize is the size of a node hash (SHA-256).
const HashSize = sha256.Size

// MaxInclusionPath bounds an inclusion path: a tree of at most 2^64-1
// leaves is at most 64 levels high.
const MaxInclusionPath = 64

// MaxConsistencyPath bounds a consistency path: RFC 9162 §2.1.4.1 bounds
// it by ceil(log2(n)) + 1, which is 65 for n near 2^64.
const MaxConsistencyPath = 65

// ErrProof is returned when a proof is malformed or does not verify.
var ErrProof = errors.New("merkle: invalid proof")

// LeafHash returns HASH(0x00 || entry).
func LeafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entry)
	return h.Sum(nil)
}

// NodeHash returns HASH(0x01 || left || right).
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Equal compares two hashes in constant time.
func Equal(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func checkPath(path [][]byte, maxLen int) error {
	if len(path) > maxLen {
		return fmt.Errorf("%w: path has %d entries, at most %d allowed", ErrProof, len(path), maxLen)
	}
	for i, p := range path {
		if len(p) != HashSize {
			return fmt.Errorf("%w: path[%d] is %d bytes, want %d", ErrProof, i, len(p), HashSize)
		}
	}
	return nil
}

// InclusionPathLen returns the length of the inclusion path for
// leafIndex in a tree of treeSize leaves (leafIndex < treeSize).
func InclusionPathLen(leafIndex, treeSize uint64) int {
	inner := bits.Len64(leafIndex ^ (treeSize - 1))
	border := bits.OnesCount64(leafIndex >> uint(inner))
	return inner + border
}

// RootFromInclusion runs RFC 9162 §2.1.3.2 and returns the root that the
// inclusion path proves leafHash into, for a tree of treeSize leaves.
// It fails if leafIndex >= treeSize, the path length doesn't match the
// tree shape, or any path element isn't HashSize bytes.
func RootFromInclusion(leafIndex, treeSize uint64, leafHash []byte, path [][]byte) ([]byte, error) {
	if leafIndex >= treeSize {
		return nil, fmt.Errorf("%w: leaf index %d not below tree size %d", ErrProof, leafIndex, treeSize)
	}
	if len(leafHash) != HashSize {
		return nil, fmt.Errorf("%w: leaf hash is %d bytes, want %d", ErrProof, len(leafHash), HashSize)
	}
	if err := checkPath(path, MaxInclusionPath); err != nil {
		return nil, err
	}
	if want := InclusionPathLen(leafIndex, treeSize); len(path) != want {
		return nil, fmt.Errorf("%w: path has %d entries, tree shape needs %d", ErrProof, len(path), want)
	}
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	for _, p := range path {
		if sn == 0 {
			return nil, fmt.Errorf("%w: path longer than the tree", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, fmt.Errorf("%w: path shorter than the tree", ErrProof)
	}
	return r, nil
}

// VerifyInclusion reports whether path proves leafHash at leafIndex into
// root for a tree of treeSize leaves.
func VerifyInclusion(leafIndex, treeSize uint64, leafHash []byte, path [][]byte, root []byte) error {
	got, err := RootFromInclusion(leafIndex, treeSize, leafHash, path)
	if err != nil {
		return err
	}
	if !Equal(got, root) {
		return fmt.Errorf("%w: computed root differs", ErrProof)
	}
	return nil
}

// RootFromConsistency runs RFC 9162 §2.1.4.2 for an older tree of size1
// leaves with root firstHash and a newer tree of size2 leaves, and
// returns the newer root the path commits to. It fails unless
// 0 < size1 < size2, the path recomputes firstHash, and the path fits
// the tree shape.
func RootFromConsistency(size1, size2 uint64, firstHash []byte, path [][]byte) ([]byte, error) {
	if size1 == 0 || size1 >= size2 {
		return nil, fmt.Errorf("%w: consistency needs 0 < size1 < size2, got %d and %d", ErrProof, size1, size2)
	}
	if len(firstHash) != HashSize {
		return nil, fmt.Errorf("%w: first hash is %d bytes, want %d", ErrProof, len(firstHash), HashSize)
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("%w: empty consistency path", ErrProof)
	}
	if err := checkPath(path, MaxConsistencyPath); err != nil {
		return nil, err
	}
	// Step 2: if size1 is an exact power of two, prepend first_hash.
	p := path
	if size1&(size1-1) == 0 {
		p = make([][]byte, 0, len(path)+1)
		p = append(p, firstHash)
		p = append(p, path...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := p[0], p[0]
	for _, c := range p[1:] {
		if sn == 0 {
			return nil, fmt.Errorf("%w: path longer than the tree", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, fmt.Errorf("%w: path shorter than the tree", ErrProof)
	}
	if !Equal(fr, firstHash) {
		return nil, fmt.Errorf("%w: path does not reproduce the older root", ErrProof)
	}
	return sr, nil
}

// VerifyConsistency reports whether path proves the tree with root
// firstHash (size1 leaves) is a prefix of the tree with root secondHash
// (size2 leaves).
func VerifyConsistency(size1, size2 uint64, firstHash, secondHash []byte, path [][]byte) error {
	got, err := RootFromConsistency(size1, size2, firstHash, path)
	if err != nil {
		return err
	}
	if !Equal(got, secondHash) {
		return fmt.Errorf("%w: computed newer root differs", ErrProof)
	}
	return nil
}

// Tree is an in-memory RFC 9162 tree over leaf hashes, for log
// operators and tests. It recomputes subtree hashes on demand and is
// meant for modest sizes, not as a production log.
type Tree struct {
	leaves [][]byte
}

// Append adds entry (hashed as a leaf) and returns its index.
func (t *Tree) Append(entry []byte) uint64 {
	t.leaves = append(t.leaves, LeafHash(entry))
	return uint64(len(t.leaves) - 1)
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.leaves)) }

// Root returns the Merkle Tree Hash of the first n leaves.
func (t *Tree) Root(n uint64) ([]byte, error) {
	if n > t.Size() {
		return nil, fmt.Errorf("%w: tree has %d leaves, asked for %d", ErrProof, t.Size(), n)
	}
	return mth(t.leaves[:n]), nil
}

// InclusionProof returns PATH(m, D[0:n]) (RFC 9162 §2.1.3.1).
func (t *Tree) InclusionProof(m, n uint64) ([][]byte, error) {
	if n > t.Size() || m >= n {
		return nil, fmt.Errorf("%w: no leaf %d in a tree of %d", ErrProof, m, n)
	}
	return path(m, t.leaves[:n]), nil
}

// ConsistencyProof returns PROOF(m, D[0:n]) (RFC 9162 §2.1.4.1).
func (t *Tree) ConsistencyProof(m, n uint64) ([][]byte, error) {
	if n > t.Size() || m == 0 || m >= n {
		return nil, fmt.Errorf("%w: consistency needs 0 < %d < %d <= %d", ErrProof, m, n, t.Size())
	}
	return subproof(m, t.leaves[:n], true), nil
}

// split returns the largest power of two smaller than n (n > 1).
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func mth(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return NodeHash(mth(leaves[:k]), mth(leaves[k:]))
}

func path(m uint64, leaves [][]byte) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := split(len(leaves))
	if m < uint64(k) {
		return append(path(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(path(m-uint64(k), leaves[k:]), mth(leaves[:k]))
}

func subproof(m uint64, leaves [][]byte, complete bool) [][]byte {
	n := uint64(len(leaves))
	if m == n {
		if complete {
			return nil
		}
		return [][]byte{mth(leaves)}
	}
	k := uint64(split(len(leaves)))
	if m <= k {
		return append(subproof(m, leaves[:k], complete), mth(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), mth(leaves[:k]))
}
