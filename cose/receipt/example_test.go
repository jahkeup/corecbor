// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package receipt_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
)

// A transparency log issues a receipt (RFC 9942) proving an entry is in
// its Merkle tree; a relying party verifies it with only the entry and
// the log's public key.
func ExampleReceipt_VerifyInclusion() {
	ctx := context.Background()
	seed := make([]byte, ed25519.SeedSize) // fixed for the example; never do this
	logKey := ed25519.NewKeyFromSeed(seed)
	logSigner, _ := cose.NewSigner(logKey, cose.WithFullySpecifiedAlgorithms())

	// The log appends entries and signs its root with a proof for one.
	var tree receipt.Tree
	entries := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("statement")}
	for _, e := range entries {
		tree.Append(e)
	}
	proof, _ := tree.InclusionProof(3, tree.Size())
	root, _ := tree.Root(tree.Size())
	issued, _ := receipt.Issue(ctx, logSigner, root, proof, cose.Headers{})
	wire, _ := issued.Marshal()

	// The relying party trusts the log's key.
	k, _ := cose.NewKeyFromPublic(logKey.Public())
	keys := cose.KeySetResolver(cose.KeySet{k})

	r, _ := receipt.Parse(wire)
	fmt.Println("tree size:", r.Inclusion[0].TreeSize, "leaf:", r.Inclusion[0].LeafIndex)
	fmt.Println("included:", r.VerifyInclusion(ctx, []byte("statement"), keys) == nil)
	err := r.VerifyInclusion(ctx, []byte("forged"), keys)
	fmt.Println("other entry rejected:", errors.Is(err, cose.ErrVerification))
	// Output:
	// tree size: 4 leaf: 3
	// included: true
	// other entry rejected: true
}
