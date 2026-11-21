// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"crypto"
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

type CredentialType int

const (
	CredentialRPK CredentialType = iota
	CredentialCWT
)

// Credential is an authentication credential (CRED_x, RFC 9528 §3.5.2).
//
// Type and CWTBytes are the v0.2 fields. The RFC 9528 path uses Raw,
// IDCred and PublicKey; when they are empty it derives them: from
// CWTBytes for CredentialCWT, or from the configured key as a CWT
// Claims Set sent by value (kccs) for CredentialRPK.
type Credential struct {
	Type     CredentialType
	CWTBytes []byte

	// Raw is CRED_x exactly as it enters the transcript: the encoded
	// CBOR item. For X.509 it is a byte string holding the DER
	// certificate; for a CCS, the encoded claims set; for a CWT, the
	// encoded token.
	Raw []byte
	// IDCred is how this credential is identified on the wire.
	IDCred IDCred
	// PublicKey is the authentication key bound by Raw: an
	// ed25519.PublicKey or *ecdsa.PublicKey for signature methods, or
	// a static DH key (*ecdh.PublicKey, or *ecdsa.PublicKey on the
	// suite's curve) for static DH methods.
	PublicKey crypto.PublicKey
}

func encodeIDCredCWT(cwtBytes []byte) ([]byte, error) {
	return cborEncodeValue(nil, cbor.Bytes(cwtBytes))
}

func extractPublicKeyFromCWT(cwtBytes []byte, issuerPub crypto.PublicKey) (crypto.PublicKey, error) {
	verifier, err := cose.NewVerifier(issuerPub)
	if err != nil {
		return nil, fmt.Errorf("%w: creating CWT verifier: %v", ErrAuthentication, err)
	}

	claims, err := cwt.Verify(cwtBytes, verifier)
	if err != nil {
		return nil, fmt.Errorf("%w: CWT verification failed: %v", ErrAuthentication, err)
	}

	// cwt decodes the cnf claim (8) into the typed Confirmation; a
	// malformed cnf fails cwt.Verify, so there is no untyped fallback.
	if claims.Confirmation == nil || claims.Confirmation.Key == nil {
		return nil, fmt.Errorf("%w: CWT has no cnf COSE_Key", ErrMessageFormat)
	}
	return claims.Confirmation.Key.PublicKey()
}
