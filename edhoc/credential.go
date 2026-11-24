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
	//
	// The key must suit the method (RFC 9528 §3.5.1). Ed25519 keys only
	// sign and ecdh keys only agree. A P-curve key may do either unless
	// the credential says otherwise: in a CCS or CWT, the cnf
	// COSE_Key's alg (a signature or a key agreement algorithm) and
	// key_ops; in an X.509 certificate, the keyUsage extension
	// (digitalSignature or keyAgreement). A key the credential restricts
	// to the other use fails with ErrAuthentication for a peer and
	// ErrStateViolation for this party's own credential.
	PublicKey crypto.PublicKey

	// coseKey is the COSE_Key a CWT's cnf claim held, when this package
	// verified the CWT; its alg and key_ops restrict the key's use.
	coseKey *cose.Key
}

func encodeIDCredCWT(cwtBytes []byte) ([]byte, error) {
	return cborEncodeValue(nil, cbor.Bytes(cwtBytes))
}

// extractPublicKeyFromCWT verifies a CWT with issuerPub, validates its
// claims with v, and returns the key in its cnf claim. Both protocols
// (RFC 9528 and the legacy pre-RFC one) pass a non-nil v.
func extractPublicKeyFromCWT(cwtBytes []byte, issuerPub crypto.PublicKey, v *cwt.Validator) (crypto.PublicKey, error) {
	_, pub, err := cwtKey(cwtBytes, issuerPub, v)
	return pub, err
}

// cwtKey is extractPublicKeyFromCWT, also returning the cnf COSE_Key.
func cwtKey(cwtBytes []byte, issuerPub crypto.PublicKey, v *cwt.Validator) (*cose.Key, crypto.PublicKey, error) {
	verifier, err := cose.NewVerifier(issuerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: creating CWT verifier: %v", ErrAuthentication, err)
	}

	claims, err := cwt.Verify(cwtBytes, verifier)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: CWT verification failed: %v", ErrAuthentication, err)
	}
	if err := v.Validate(claims); err != nil {
		return nil, nil, fmt.Errorf("%w: CWT claims: %w", ErrAuthentication, err)
	}

	// cwt decodes the cnf claim (8) into the typed Confirmation; a
	// malformed cnf fails cwt.Verify, so there is no untyped fallback.
	if claims.Confirmation == nil || claims.Confirmation.Key == nil {
		return nil, nil, fmt.Errorf("%w: CWT has no cnf COSE_Key", ErrMessageFormat)
	}
	pub, err := claims.Confirmation.Key.PublicKey()
	if err != nil {
		return nil, nil, err
	}
	return claims.Confirmation.Key, pub, nil
}
