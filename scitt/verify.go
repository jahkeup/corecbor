// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package scitt

import (
	"context"
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cose/receipt"
	"github.com/jahkeup/corecbor/cwt"
)

// ErrInsufficientReceipts is returned when fewer receipts verify than a
// verification requires. It wraps cose.ErrVerification.
var ErrInsufficientReceipts = fmt.Errorf("scitt: not enough receipts verify: %w", cose.ErrVerification)

// errNoKeys is wrapped when a verification is missing a key resolver.
var errNoKeys = errors.New("no key resolver")

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// IssuerKeys resolves the issuer's verification keys. Required
	// unless SkipIssuerSignature is set.
	IssuerKeys cose.KeyResolver
	// SkipIssuerSignature verifies receipts only, which RFC 9943 §7.1
	// permits for a relying party that trusts the transparency
	// service's registration policy. The statement's shape is still
	// checked.
	SkipIssuerSignature bool
	// ServiceKeys resolves trusted transparency services' receipt keys.
	// Required.
	ServiceKeys cose.KeyResolver
	// MinReceipts is how many receipts must verify; 0 means 1.
	MinReceipts int
	// Payload is a detached statement payload (or, for a hash
	// envelope, the detached digest). Preimage is a hash envelope's
	// preimage; when given, the digest is checked against it.
	Payload, Preimage []byte
	// IssuerOptions and ServiceOptions apply to the issuer and receipt
	// signature checks (for example cose.WithAllowedAlgorithms).
	IssuerOptions, ServiceOptions []cose.VerifierOption
}

// VerifyTransparent verifies a transparent statement: the issuer's
// signature (keys from issuerKeys) and at least minReceipts receipts
// from trusted transparency services (keys from serviceKeys; minReceipts
// <= 0 means 1). Each receipt must carry protected CWT Claims (RFC 9943
// §6) and prove inclusion of the statement's Entry. The payload must be
// attached; use Verify for detached payloads.
func VerifyTransparent(ctx context.Context, data []byte, issuerKeys, serviceKeys cose.KeyResolver, minReceipts int) (*Statement, error) {
	return Verify(ctx, data, VerifyOptions{IssuerKeys: issuerKeys, ServiceKeys: serviceKeys, MinReceipts: minReceipts})
}

// Verify verifies a transparent statement under o. It returns the
// statement only if its shape is valid, the issuer signature verifies
// (unless skipped), and at least o.MinReceipts receipts verify; a
// shortfall is ErrInsufficientReceipts, wrapping the last receipt
// failure.
func Verify(ctx context.Context, data []byte, o VerifyOptions) (*Statement, error) {
	st, err := ParseStatement(data)
	if err != nil {
		return nil, err
	}
	if !o.SkipIssuerSignature {
		if err := verifyIssuer(ctx, st, o); err != nil {
			return nil, err
		}
	}
	if o.ServiceKeys == nil {
		return nil, fmt.Errorf("%w: service keys: %w", cose.ErrVerification, errNoKeys)
	}
	need := o.MinReceipts
	if need <= 0 {
		need = 1
	}
	rs, err := receipt.Receipts(st.Msg)
	if err != nil {
		return nil, err
	}
	entry, err := Entry(st.Msg)
	if err != nil {
		return nil, err
	}
	got := 0
	var last error
	for i, r := range rs {
		if err := verifyReceipt(ctx, r, entry, o); err != nil {
			last = fmt.Errorf("receipt %d: %w", i, err)
			continue
		}
		got++
	}
	if got < need {
		if last != nil {
			return nil, fmt.Errorf("%w: %d of %d required verified: %w", ErrInsufficientReceipts, got, need, last)
		}
		return nil, fmt.Errorf("%w: %d of %d required verified", ErrInsufficientReceipts, got, need)
	}
	return st, nil
}

func verifyIssuer(ctx context.Context, st *Statement, o VerifyOptions) error {
	if o.IssuerKeys == nil {
		return fmt.Errorf("%w: issuer keys: %w", cose.ErrVerification, errNoKeys)
	}
	msg := st.Msg
	if st.HashEnvelope != nil {
		_, err := cose.VerifySign1HashEnvelope(ctx, msg, o.Payload, o.Preimage, o.IssuerKeys, o.IssuerOptions...)
		return err
	}
	if msg.Payload != nil {
		return cose.VerifySign1(ctx, msg, o.IssuerKeys, o.IssuerOptions...)
	}
	if o.Payload == nil {
		return cose.ErrMissingPayload
	}
	return cose.VerifySign1Detached(ctx, msg, o.Payload, o.IssuerKeys, o.IssuerOptions...)
}

func verifyReceipt(ctx context.Context, r *receipt.Receipt, entry []byte, o VerifyOptions) error {
	claims, ok, err := cwt.ClaimsFromHeaders(&r.Msg.Protected)
	if err != nil {
		return err
	}
	if !ok || claims.Issuer == "" || claims.Subject == "" {
		return fmt.Errorf("%w: receipt without protected CWT Claims iss and sub", ErrInvalidStatement)
	}
	return r.VerifyInclusion(ctx, entry, o.ServiceKeys, o.ServiceOptions...)
}
