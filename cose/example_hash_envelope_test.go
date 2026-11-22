// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

import (
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// A Hash Envelope (RFC 9995) signs the digest of a large artifact
// instead of the artifact. The verifier checks the signature over the
// digest and, when it has the artifact, that the digest matches it.
func ExampleSigner_SignHashEnvelope() {
	key := exampleKey(7)
	signer, _ := cose.NewSigner(key, cose.WithFullySpecifiedAlgorithms())
	verifier, _ := cose.NewVerifier(key.Public())

	sbom := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	env := cose.HashEnvelope{
		HashAlg:             cose.AlgSHA256,
		PreimageContentType: "application/spdx+json",
		Location:            "https://sbom.example/manifest.spdx.json",
	}
	msg, _ := signer.SignHashEnvelope(sbom, env, false)
	wire, _ := cose.MarshalSign1(msg)

	received, _ := cose.UnmarshalSign1(wire)
	got, err := verifier.VerifyHashEnvelope(received, nil, sbom)
	fmt.Println("verified:", err == nil)
	fmt.Println("preimage type:", got.PreimageContentType)

	_, err = verifier.VerifyHashEnvelope(received, nil, []byte("tampered"))
	fmt.Println("tampered preimage rejected:", errors.Is(err, cose.ErrVerification))
	// Output:
	// verified: true
	// preimage type: application/spdx+json
	// tampered preimage rejected: true
}
