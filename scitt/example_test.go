// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package scitt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
	"github.com/jahkeup/corecbor/scitt"
)

func exampleKey(kid string) (*cose.Signer, cose.KeyResolver) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := cose.NewSigner(priv)
	k, _ := cose.NewKeyFromPublic(&priv.PublicKey)
	k.SetID([]byte(kid))
	return s, cose.KeySetResolver(cose.KeySet{k})
}

// Issue a signed statement, register it with a transparency service,
// attach the receipt and verify the transparent statement.
func ExampleVerifyTransparent() {
	ctx := context.Background()
	issuerSigner, issuerKeys := exampleKey("issuer-key")
	serviceSigner, serviceKeys := exampleKey("service-key")

	// Issuer: sign the statement.
	st, err := scitt.Issue(ctx, issuerSigner, []byte(`{"build":"ok"}`), scitt.IssueOptions{
		Issuer:      "https://issuer.example",
		Subject:     "pkg:example/widget@1.0",
		ContentType: "application/json",
		KeyID:       []byte("issuer-key"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Transparency service: append the entry and issue a receipt.
	entry, _ := scitt.Entry(st.Msg)
	var log receipt.Tree
	log.Append([]byte("an earlier entry"))
	index := log.Append(entry)
	proof, _ := log.InclusionProof(index, log.Size())
	root, _ := log.Root(log.Size())
	prot, _ := scitt.ReceiptHeaders("https://ts.example", "pkg:example/widget@1.0")
	prot.SetKeyID([]byte("service-key"))
	r, err := receipt.Issue(ctx, serviceSigner, root, proof, prot)
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = receipt.Attach(st.Msg, r)
	transparent, _ := cose.MarshalSign1(st.Msg)

	// Relying party: verify the issuer signature and one receipt.
	got, err := scitt.VerifyTransparent(ctx, transparent, issuerKeys, serviceKeys, 1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(got.Claims.Issuer, got.Claims.Subject)
	// Output: https://issuer.example pkg:example/widget@1.0
}
