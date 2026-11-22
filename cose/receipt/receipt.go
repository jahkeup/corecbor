// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package receipt implements COSE Receipts (RFC 9942) for the
// RFC9162_SHA256 verifiable data structure: signed Merkle Tree roots
// that carry inclusion or consistency proofs (RFC 9162 §2.1).
//
// A receipt is a tagged COSE_Sign1 whose protected bucket names the
// verifiable data structure (vds, label 395) and whose unprotected
// bucket carries the proofs (vdp, label 396). Its payload is detached:
// the verifier recomputes the Merkle Tree root from the proof and the
// entry, then verifies the signature with that root as the payload.
// Receipts are attached to the statement they cover under the receipts
// header (label 394).
package receipt

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt/internal/merkle"
	"github.com/jahkeup/corecbor/wire"
)

// COSE header labels and registry values from RFC 9942 (checked against
// the IANA COSE Header Parameters, Verifiable Data Structure Algorithms
// and Verifiable Data Structure Proofs registries).
const (
	// HeaderReceipts (394) carries receipts in a statement's headers.
	HeaderReceipts int64 = 394
	// HeaderVDS (395) names the verifiable data structure; protected.
	HeaderVDS int64 = 395
	// HeaderVDP (396) carries the verifiable data structure proofs;
	// unprotected.
	HeaderVDP int64 = 396

	// VDSRFC9162SHA256 is the RFC 9162 binary Merkle Tree with SHA-256.
	VDSRFC9162SHA256 int64 = 1

	// ProofInclusion and ProofConsistency are the RFC9162_SHA256 proof
	// types (keys of the vdp map).
	ProofInclusion   int64 = -1
	ProofConsistency int64 = -2
)

// HashSize is the size of an RFC9162_SHA256 tree hash (SHA-256).
const HashSize = merkle.HashSize

// ErrProof is returned when a Merkle proof doesn't hold: it is malformed
// for the tree shape, or the roots it yields disagree. It wraps
// cose.ErrVerification.
var ErrProof = fmt.Errorf("receipt: Merkle proof does not verify: %w", cose.ErrVerification)

// InclusionProof is an RFC9162_SHA256 inclusion proof: the entry at
// LeafIndex is in the tree of TreeSize leaves (RFC 9942 §5.2).
type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      [][]byte
}

// ConsistencyProof is an RFC9162_SHA256 consistency proof: the tree of
// TreeSize1 leaves is a prefix of the tree of TreeSize2 leaves (RFC 9942
// §5.3).
type ConsistencyProof struct {
	TreeSize1, TreeSize2 uint64
	Path                 [][]byte
}

// Receipt is a parsed RFC 9942 receipt. A receipt carries either
// inclusion proofs or consistency proofs, never both (RFC 9942 Figure 1).
type Receipt struct {
	Msg         *cose.Sign1
	VDS         int64
	Inclusion   []InclusionProof
	Consistency []ConsistencyProof
}

// Parse decodes a receipt with cose.RecommendedDecodeLimits. It checks
// the RFC 9942 shape: a tagged COSE_Sign1 (tag 18) with a detached
// (null) payload, vds in the protected bucket only, vdp in the
// unprotected bucket only, and well-formed RFC9162_SHA256 proofs. An
// unregistered vds is cose.ErrUnsupportedAlgorithm; any other defect is
// cose.ErrMalformed.
func Parse(data []byte) (*Receipt, error) {
	if !isTaggedSign1(data) {
		return nil, fmt.Errorf("%w: receipt is not a tagged COSE_Sign1 (tag 18)", cose.ErrMalformed)
	}
	msg, err := cose.UnmarshalSign1With(data, cose.RecommendedDecodeLimits)
	if err != nil {
		return nil, err
	}
	return fromSign1(msg)
}

// isTaggedSign1 reports whether data starts with tag 18, after any
// self-describe tags (55799) the decoder also strips.
func isTaggedSign1(data []byte) bool {
	for {
		h := wire.ParseHead(data)
		if h.N == 0 || h.Major != wire.MajorTag {
			return false
		}
		if h.Arg != corecbor.TagSelfDescribe {
			return h.Arg == corecbor.TagCOSESign1
		}
		data = data[h.N:]
	}
}

func fromSign1(msg *cose.Sign1) (*Receipt, error) {
	if msg.Payload != nil {
		return nil, fmt.Errorf("%w: receipt payload must be detached (null)", cose.ErrMalformed)
	}
	if msg.Unprotected.Get(HeaderVDS) != nil {
		return nil, fmt.Errorf("%w: vds (395) in the unprotected bucket", cose.ErrMalformed)
	}
	if msg.Protected.Get(HeaderVDP) != nil {
		return nil, fmt.Errorf("%w: vdp (396) in the protected bucket", cose.ErrMalformed)
	}
	vds, ok := msg.Protected.Get(HeaderVDS).(int64)
	if !ok {
		return nil, fmt.Errorf("%w: receipt without an integer vds (395) in the protected bucket", cose.ErrMalformed)
	}
	if vds != VDSRFC9162SHA256 {
		return nil, fmt.Errorf("%w: verifiable data structure %d", cose.ErrUnsupportedAlgorithm, vds)
	}
	vdp, ok := msg.Unprotected.Get(HeaderVDP).(corecbor.Value)
	if !ok || vdp.Kind != corecbor.KindMap {
		return nil, fmt.Errorf("%w: receipt without a vdp (396) map in the unprotected bucket", cose.ErrMalformed)
	}
	r := &Receipt{Msg: msg, VDS: vds}
	for _, e := range vdp.Map() {
		label, err := e.Key.Int64()
		if err != nil {
			return nil, fmt.Errorf("%w: vdp key is not an integer", cose.ErrMalformed)
		}
		items, err := proofItems(e.Value, label)
		if err != nil {
			return nil, err
		}
		switch label {
		case ProofInclusion:
			for _, b := range items {
				p, err := decodeInclusion(b)
				if err != nil {
					return nil, err
				}
				r.Inclusion = append(r.Inclusion, p)
			}
		case ProofConsistency:
			for _, b := range items {
				p, err := decodeConsistency(b)
				if err != nil {
					return nil, err
				}
				r.Consistency = append(r.Consistency, p)
			}
		default:
			return nil, fmt.Errorf("%w: proof type %d is not defined for RFC9162_SHA256", cose.ErrMalformed, label)
		}
	}
	switch {
	case len(r.Inclusion) == 0 && len(r.Consistency) == 0:
		return nil, fmt.Errorf("%w: receipt carries no proofs", cose.ErrMalformed)
	case len(r.Inclusion) > 0 && len(r.Consistency) > 0:
		return nil, fmt.Errorf("%w: receipt carries both inclusion and consistency proofs", cose.ErrMalformed)
	}
	return r, nil
}

// proofItems returns the bstr elements of a vdp value: [+ bstr .cbor ...].
func proofItems(v corecbor.Value, label int64) ([][]byte, error) {
	if v.Kind != corecbor.KindArray || len(v.Array()) == 0 {
		return nil, fmt.Errorf("%w: vdp proof type %d must be a non-empty array", cose.ErrMalformed, label)
	}
	out := make([][]byte, 0, len(v.Array()))
	for _, it := range v.Array() {
		if it.Kind != corecbor.KindBytes {
			return nil, fmt.Errorf("%w: vdp proof type %d element is not a bstr", cose.ErrMalformed, label)
		}
		out = append(out, it.BytesVal())
	}
	return out, nil
}

// proofDecoder decodes the small proof structures inside vdp bstrs.
var proofDecoder = corecbor.NewDecoder(
	corecbor.WithoutInternalArena(),
	corecbor.WithMaxNestingDepth(4),
	corecbor.WithMaxArrayLength(merkle.MaxConsistencyPath),
	corecbor.WithMaxByteStringLength(merkle.HashSize),
)

// proofContent decodes [uint, uint, [* bstr]] from a vdp element.
func proofContent(b []byte, maxPath int) (uint64, uint64, [][]byte, error) {
	v, err := proofDecoder.Decode(b)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: proof: %w", cose.ErrMalformed, err)
	}
	a := v.Array()
	if v.Kind != corecbor.KindArray || len(a) != 3 {
		return 0, 0, nil, fmt.Errorf("%w: proof must be a 3-element array", cose.ErrMalformed)
	}
	x, err1 := a[0].Uint64()
	y, err2 := a[1].Uint64()
	if err1 != nil || err2 != nil || a[0].Kind != corecbor.KindUint || a[1].Kind != corecbor.KindUint {
		return 0, 0, nil, fmt.Errorf("%w: proof sizes must be uint", cose.ErrMalformed)
	}
	if a[2].Kind != corecbor.KindArray {
		return 0, 0, nil, fmt.Errorf("%w: proof path must be an array", cose.ErrMalformed)
	}
	if len(a[2].Array()) > maxPath {
		return 0, 0, nil, fmt.Errorf("%w: proof path has %d entries, at most %d allowed", cose.ErrMalformed, len(a[2].Array()), maxPath)
	}
	path := make([][]byte, 0, len(a[2].Array()))
	for _, n := range a[2].Array() {
		if n.Kind != corecbor.KindBytes || len(n.BytesVal()) != merkle.HashSize {
			return 0, 0, nil, fmt.Errorf("%w: proof path element must be a %d-byte bstr", cose.ErrMalformed, merkle.HashSize)
		}
		path = append(path, bytes.Clone(n.BytesVal()))
	}
	return x, y, path, nil
}

func decodeInclusion(b []byte) (InclusionProof, error) {
	size, index, path, err := proofContent(b, merkle.MaxInclusionPath)
	if err != nil {
		return InclusionProof{}, err
	}
	p := InclusionProof{TreeSize: size, LeafIndex: index, Path: path}
	if err := p.check(); err != nil {
		return InclusionProof{}, err
	}
	return p, nil
}

func decodeConsistency(b []byte) (ConsistencyProof, error) {
	s1, s2, path, err := proofContent(b, merkle.MaxConsistencyPath)
	if err != nil {
		return ConsistencyProof{}, err
	}
	p := ConsistencyProof{TreeSize1: s1, TreeSize2: s2, Path: path}
	if err := p.check(); err != nil {
		return ConsistencyProof{}, err
	}
	return p, nil
}

// check validates the proof's shape: leaf index below tree size, and a
// path whose length fits the tree.
func (p InclusionProof) check() error {
	if p.LeafIndex >= p.TreeSize {
		return fmt.Errorf("%w: leaf index %d not below tree size %d", cose.ErrMalformed, p.LeafIndex, p.TreeSize)
	}
	if want := merkle.InclusionPathLen(p.LeafIndex, p.TreeSize); len(p.Path) != want {
		return fmt.Errorf("%w: inclusion path has %d entries, tree shape needs %d", cose.ErrMalformed, len(p.Path), want)
	}
	for _, n := range p.Path {
		if len(n) != merkle.HashSize {
			return fmt.Errorf("%w: inclusion path element is %d bytes", cose.ErrMalformed, len(n))
		}
	}
	return nil
}

func (p ConsistencyProof) check() error {
	if p.TreeSize1 == 0 || p.TreeSize1 >= p.TreeSize2 {
		return fmt.Errorf("%w: consistency needs 0 < size1 < size2, got %d and %d", cose.ErrMalformed, p.TreeSize1, p.TreeSize2)
	}
	if len(p.Path) == 0 || len(p.Path) > merkle.MaxConsistencyPath {
		return fmt.Errorf("%w: consistency path has %d entries", cose.ErrMalformed, len(p.Path))
	}
	for _, n := range p.Path {
		if len(n) != merkle.HashSize {
			return fmt.Errorf("%w: consistency path element is %d bytes", cose.ErrMalformed, len(n))
		}
	}
	return nil
}

func (p InclusionProof) encode() ([]byte, error) {
	return encodeProof(p.TreeSize, p.LeafIndex, p.Path)
}

func (p ConsistencyProof) encode() ([]byte, error) {
	return encodeProof(p.TreeSize1, p.TreeSize2, p.Path)
}

var proofEncoder = corecbor.NewShared(corecbor.ModeCoreDeterministic)

func encodeProof(a, b uint64, path [][]byte) ([]byte, error) {
	items := make([]corecbor.Value, len(path))
	for i, n := range path {
		items[i] = corecbor.Bytes(n)
	}
	return proofEncoder.Encode(nil, corecbor.MakeArray(corecbor.Uint(a), corecbor.Uint(b), corecbor.MakeArrayFromSlice(items)))
}

// Marshal encodes the receipt as a tagged COSE_Sign1.
func (r *Receipt) Marshal() ([]byte, error) {
	return cose.MarshalSign1(r.Msg)
}

// LeafHash returns the RFC 9162 leaf hash of entry: SHA-256(0x00 || entry).
func LeafHash(entry []byte) []byte { return merkle.LeafHash(entry) }

// InclusionRoot returns the Merkle Tree root the receipt's inclusion
// proofs yield for the entry with leafHash. Every proof must yield the
// same root; otherwise, or if the receipt has no inclusion proof, it
// returns an error (ErrProof, or cose.ErrMalformed for no proof).
func (r *Receipt) InclusionRoot(leafHash []byte) ([]byte, error) {
	if len(r.Inclusion) == 0 {
		return nil, fmt.Errorf("%w: receipt has no inclusion proof", cose.ErrMalformed)
	}
	var root []byte
	for i, p := range r.Inclusion {
		got, err := merkle.RootFromInclusion(p.LeafIndex, p.TreeSize, leafHash, p.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: inclusion proof %d: %w", ErrProof, i, err)
		}
		if root != nil && !merkle.Equal(root, got) {
			return nil, fmt.Errorf("%w: inclusion proofs yield different roots", ErrProof)
		}
		root = got
	}
	return root, nil
}

// VerifyInclusion verifies that entry is in the log the receipt
// attests: each inclusion proof is applied to the entry's RFC 9162 leaf
// hash, and the signature is verified, with keys resolved by keys, over
// the root they all yield (RFC 9942 §5.2.1). It returns nil only if
// every proof and the signature verify; any failure wraps
// cose.ErrVerification.
func (r *Receipt) VerifyInclusion(ctx context.Context, entry []byte, keys cose.KeyResolver, opts ...cose.VerifierOption) error {
	return r.VerifyInclusionHash(ctx, merkle.LeafHash(entry), keys, opts...)
}

// VerifyInclusionHash is VerifyInclusion for a precomputed leaf hash,
// for log profiles whose leaf isn't SHA-256(0x00 || entry) of a single
// byte string.
func (r *Receipt) VerifyInclusionHash(ctx context.Context, leafHash []byte, keys cose.KeyResolver, opts ...cose.VerifierOption) error {
	root, err := r.InclusionRoot(leafHash)
	if err != nil {
		return err
	}
	return cose.VerifySign1Detached(ctx, r.Msg, root, keys, opts...)
}

// VerifyConsistencyFrom verifies a consistency receipt against a
// trusted older root: each consistency proof is applied to oldRoot, and
// the signature is verified over the newer root they all yield
// (RFC 9942 §5.3.1). It returns that newer root.
func (r *Receipt) VerifyConsistencyFrom(ctx context.Context, oldRoot []byte, keys cose.KeyResolver, opts ...cose.VerifierOption) ([]byte, error) {
	if len(r.Consistency) == 0 {
		return nil, fmt.Errorf("%w: receipt has no consistency proof", cose.ErrMalformed)
	}
	var newRoot []byte
	for i, p := range r.Consistency {
		got, err := merkle.RootFromConsistency(p.TreeSize1, p.TreeSize2, oldRoot, p.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: consistency proof %d: %w", ErrProof, i, err)
		}
		if newRoot != nil && !merkle.Equal(newRoot, got) {
			return nil, fmt.Errorf("%w: consistency proofs yield different roots", ErrProof)
		}
		newRoot = got
	}
	if err := cose.VerifySign1Detached(ctx, r.Msg, newRoot, keys, opts...); err != nil {
		return nil, err
	}
	return newRoot, nil
}

// VerifyConsistency verifies that the log only grew between two
// receipts, the way RFC 9942 §5.3.1 describes: older (an inclusion
// receipt) is verified for olderEntry, which yields the older root; the
// consistency proofs in newer are applied to that root; and newer's
// signature is verified over the resulting newer root. The older tree
// size must match each consistency proof's first size.
func VerifyConsistency(ctx context.Context, older *Receipt, olderEntry []byte, newer *Receipt, keys cose.KeyResolver, opts ...cose.VerifierOption) error {
	if err := older.VerifyInclusion(ctx, olderEntry, keys, opts...); err != nil {
		return err
	}
	oldRoot, err := older.InclusionRoot(merkle.LeafHash(olderEntry))
	if err != nil {
		return err
	}
	for _, p := range newer.Consistency {
		for _, q := range older.Inclusion {
			if p.TreeSize1 != q.TreeSize {
				return fmt.Errorf("%w: consistency proof starts at size %d, older receipt is for size %d", ErrProof, p.TreeSize1, q.TreeSize)
			}
		}
	}
	_, err = newer.VerifyConsistencyFrom(ctx, oldRoot, keys, opts...)
	return err
}

// Issue signs root as an inclusion receipt carrying proof. It is for
// log operators (and tests); protected is merged with vds (395) = 1,
// and the payload is detached. The proof's shape is checked, but not
// that it reaches root: the issuer is trusted to pass a consistent
// pair.
//
// Experimental: issuing is outside RFC 9942's verifier-side scope and
// may change.
func Issue(ctx context.Context, s *cose.Signer, root []byte, proof InclusionProof, protected cose.Headers) (*Receipt, error) {
	if err := proof.check(); err != nil {
		return nil, err
	}
	b, err := proof.encode()
	if err != nil {
		return nil, err
	}
	return issue(ctx, s, root, ProofInclusion, b, protected, func(r *Receipt) { r.Inclusion = []InclusionProof{proof} })
}

// IssueConsistency signs newRoot (the root at proof.TreeSize2) as a
// consistency receipt carrying proof.
//
// Experimental: see Issue.
func IssueConsistency(ctx context.Context, s *cose.Signer, newRoot []byte, proof ConsistencyProof, protected cose.Headers) (*Receipt, error) {
	if err := proof.check(); err != nil {
		return nil, err
	}
	b, err := proof.encode()
	if err != nil {
		return nil, err
	}
	return issue(ctx, s, newRoot, ProofConsistency, b, protected, func(r *Receipt) { r.Consistency = []ConsistencyProof{proof} })
}

func issue(ctx context.Context, s *cose.Signer, root []byte, kind int64, proof []byte, protected cose.Headers, set func(*Receipt)) (*Receipt, error) {
	if len(root) != merkle.HashSize {
		return nil, fmt.Errorf("%w: root is %d bytes, want %d", cose.ErrMalformed, len(root), merkle.HashSize)
	}
	if v := protected.Get(HeaderVDS); v != nil && v != VDSRFC9162SHA256 {
		return nil, fmt.Errorf("%w: protected vds %v, this package issues RFC9162_SHA256 (1)", cose.ErrUnsupportedAlgorithm, v)
	}
	if protected.Get(HeaderVDP) != nil {
		return nil, fmt.Errorf("%w: vdp (396) must not be protected", cose.ErrMalformed)
	}
	msg := &cose.Sign1{Protected: protected, Payload: root}
	if err := msg.Protected.SetChecked(HeaderVDS, VDSRFC9162SHA256); err != nil {
		return nil, err
	}
	vdp := corecbor.MakeMap(corecbor.MapEntry{
		Key:   corecbor.NegInt(uint64(-1 - kind)),
		Value: corecbor.MakeArray(corecbor.Bytes(proof)),
	})
	if err := msg.Unprotected.SetChecked(HeaderVDP, vdp); err != nil {
		return nil, err
	}
	if err := s.Sign1Context(ctx, msg); err != nil {
		return nil, err
	}
	msg.Payload = nil
	r := &Receipt{Msg: msg, VDS: VDSRFC9162SHA256}
	set(r)
	return r, nil
}

// Attach appends receipts to stmt's receipts header (label 394) in the
// unprotected bucket, each encoded as bstr .cbor Receipt (RFC 9942 §4.3).
// The statement's signature is unaffected.
func Attach(stmt *cose.Sign1, receipts ...*Receipt) error {
	existing, err := rawReceipts(&stmt.Unprotected)
	if err != nil {
		return err
	}
	items := make([]any, 0, len(existing)+len(receipts))
	for _, b := range existing {
		items = append(items, b)
	}
	for _, r := range receipts {
		b, err := r.Marshal()
		if err != nil {
			return err
		}
		items = append(items, b)
	}
	return stmt.Unprotected.SetChecked(HeaderReceipts, items)
}

// Receipts parses the receipts attached to stmt (label 394), from the
// unprotected bucket and then the protected one, in order. A malformed
// receipts header or receipt is an error; receipts are returned
// unverified.
func Receipts(stmt *cose.Sign1) ([]*Receipt, error) {
	var out []*Receipt
	for _, h := range []*cose.Headers{&stmt.Unprotected, &stmt.Protected} {
		raw, err := rawReceipts(h)
		if err != nil {
			return nil, err
		}
		for i, b := range raw {
			r, err := Parse(b)
			if err != nil {
				return nil, fmt.Errorf("receipt %d: %w", i, err)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// errReceiptsHeader is wrapped by malformed receipts headers.
var errReceiptsHeader = errors.New("receipts header (394) must be an array of bstr")

// rawReceipts returns the bstr elements of h's receipts header, whether
// decoded (corecbor.Value) or set locally ([]any of []byte).
func rawReceipts(h *cose.Headers) ([][]byte, error) {
	switch v := h.Get(HeaderReceipts).(type) {
	case nil:
		return nil, nil
	case corecbor.Value:
		if v.Kind != corecbor.KindArray {
			return nil, fmt.Errorf("%w: %w", cose.ErrMalformed, errReceiptsHeader)
		}
		out := make([][]byte, 0, len(v.Array()))
		for _, it := range v.Array() {
			if it.Kind != corecbor.KindBytes {
				return nil, fmt.Errorf("%w: %w", cose.ErrMalformed, errReceiptsHeader)
			}
			out = append(out, it.BytesVal())
		}
		return out, nil
	case []any:
		out := make([][]byte, 0, len(v))
		for _, it := range v {
			b, ok := it.([]byte)
			if !ok {
				return nil, fmt.Errorf("%w: %w", cose.ErrMalformed, errReceiptsHeader)
			}
			out = append(out, b)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %w", cose.ErrMalformed, errReceiptsHeader)
	}
}
