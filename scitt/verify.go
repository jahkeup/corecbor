// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package scitt

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// MinReceipts is how many receipts from distinct transparency
	// services must verify; 0 means 1. A service is identified by its
	// receipt's issuer (the iss of the receipt's protected CWT Claims),
	// so a receipt attached twice, or several receipts from one
	// service, count once. ServiceKeys should resolve a key only for
	// the issuer it belongs to; one key that verifies receipts naming
	// several issuers would let one service stand for several.
	MinReceipts int
	// Payload is a detached statement payload (or, for a hash
	// envelope, the detached digest). Preimage is a hash envelope's
	// preimage; when given, the digest is checked against it.
	Payload, Preimage []byte
	// IssuerOptions and ServiceOptions apply to the issuer and receipt
	// signature checks (for example cose.WithAllowedAlgorithms).
	IssuerOptions, ServiceOptions []cose.VerifierOption
	// Validator checks the statement's CWT Claims: its validity period
	// (exp, nbf; RFC 9943 §7.1) and aud. nil means DefaultValidator().
	// To check a statement as of another time, as an auditor might,
	// pass a Validator with Now set.
	Validator *cwt.Validator
}

// DefaultValidator is the statement validator Verify uses when
// VerifyOptions.Validator is nil: a statement is rejected on or after
// its exp and before its nbf, with 60 seconds of leeway; exp is not
// required, since signed statements commonly carry none. As for every
// cwt.Validator, a statement carrying aud is rejected unless the
// Validator lists one of its audiences.
func DefaultValidator() *cwt.Validator {
	return &cwt.Validator{Leeway: 60 * time.Second}
}

// VerifyTransparent verifies a transparent statement: the issuer's
// signature (keys from issuerKeys) and receipts from at least
// minReceipts distinct trusted transparency services (keys from
// serviceKeys; minReceipts <= 0 means 1; see VerifyOptions.MinReceipts).
// Each receipt must carry protected CWT Claims (RFC 9943 §6) and prove
// inclusion of the statement's Entry. The statement's exp and nbf are
// checked with DefaultValidator. The payload must be attached; use
// Verify for detached payloads.
func VerifyTransparent(ctx context.Context, data []byte, issuerKeys, serviceKeys cose.KeyResolver, minReceipts int) (*Statement, error) {
	return Verify(ctx, data, VerifyOptions{IssuerKeys: issuerKeys, ServiceKeys: serviceKeys, MinReceipts: minReceipts})
}

// Verify verifies a transparent statement under o. It returns the
// statement only if its shape is valid, the issuer signature verifies
// (unless skipped), its CWT Claims pass o.Validator (by default
// DefaultValidator: exp and nbf), and receipts from at least
// o.MinReceipts distinct transparency services verify; a shortfall is
// ErrInsufficientReceipts, wrapping the last receipt failure.
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
	v := o.Validator
	if v == nil {
		v = DefaultValidator()
	}
	if err := v.Validate(st.Claims); err != nil {
		return nil, fmt.Errorf("scitt: statement claims: %w", err)
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
	seen := map[string]bool{} // receipt issuers already counted
	got := 0
	var last error
	for i, r := range rs {
		iss, err := verifyReceipt(ctx, r, entry, o)
		if err != nil {
			last = fmt.Errorf("receipt %d: %w", i, err)
			continue
		}
		if !seen[iss] {
			seen[iss] = true
			got++
		}
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

// verifyReceipt verifies r and returns its issuer, the identity
// MinReceipts counts.
func verifyReceipt(ctx context.Context, r *receipt.Receipt, entry []byte, o VerifyOptions) (string, error) {
	claims, ok, err := cwt.ClaimsFromHeaders(&r.Msg.Protected)
	if err != nil {
		return "", err
	}
	if !ok || claims.Issuer == "" || claims.Subject == "" {
		return "", fmt.Errorf("%w: receipt without protected CWT Claims iss and sub", ErrInvalidStatement)
	}
	// RFC 9943 §6: a receipt is a signed statement; the same key
	// identification rule applies.
	if err := checkIssuerKey(r.Msg, claims); err != nil {
		return "", fmt.Errorf("receipt: %w", err)
	}
	if err := r.VerifyInclusion(ctx, entry, o.ServiceKeys, o.ServiceOptions...); err != nil {
		return "", err
	}
	return claims.Issuer, nil
}
