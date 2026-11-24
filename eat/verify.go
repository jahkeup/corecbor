// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"context"
	"fmt"
	"mime"
	"strings"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/wire"
)

// VerifyOptions configures VerifyToken. The zero value has no key
// (VerifyToken returns cwt.ErrKeyResolution) and validates with
// cwt.NewValidator().
type VerifyOptions struct {
	// Keys resolves the verification key. Required.
	Keys cose.KeyResolver

	// Validator validates the CWT claims (exp, nbf, iat, aud, ...). nil
	// means cwt.NewValidator().
	Validator *cwt.Validator

	// AllowedAlgorithms restricts the protected alg; it is passed to
	// cose.WithAllowedAlgorithms. Empty: the resolved key decides.
	AllowedAlgorithms []cose.Algorithm

	// RequireTag requires the outer CWT tag 61.
	RequireTag bool

	// MaxNesting bounds nested tokens (a payload that is itself a
	// tagged COSE_Sign1 or CWT, or cty naming a CWT or EAT, RFC 8392
	// §7.2 step 6). 0 means 1; negative forbids nesting.
	MaxNesting int

	// Options adjust claims decoding (WithKeepAsReceived,
	// WithLegacyDraftClaimKeys).
	Options []Option
}

// Token is a verified EAT and its COSE envelope.
type Token struct {
	Protected   *cose.Headers
	Unprotected *cose.Headers
	Claims      *Claims
	Tagged      bool   // outer tag 61 was present
	Nested      *Token // the inner token of a nested CWT; Claims are its claims
}

// tokenDecodeLimits bounds the COSE envelope of a token (claims decoding
// has its own 8 MiB budget).
var tokenDecodeLimits = cose.RecommendedDecodeLimits

// legacyDecodeLimits bounds the envelope for Verify, the v0.2.2 entry
// point: its budget matches the claims decoder's, so any token whose
// claims Verify could decode before still fits.
var legacyDecodeLimits = cose.DecodeLimits{MemoryBudget: decodeBudget}

// VerifyToken is the recommended entry point for a signed CBOR EAT
// (RFC 9711 §3): a COSE_Sign1, tagged or untagged, optionally wrapped
// in CWT tag 61 (which must be followed by a COSE tag, RFC 8392 §7.2).
// It decodes the envelope with cose.RecommendedDecodeLimits, checks the
// typ header (application/eat+cwt or application/cwt, by media type or
// CoAP content format, when present), resolves the key through
// opts.Keys and verifies the signature, then decodes the claims,
// refuses a symmetric cnf key by value (cwt.ErrSymmetricKeyNotEncrypted,
// RFC 8747 §3.2), and validates them: opts.Validator for the CWT claims
// and Claims.Validate for RFC 9711's value rules.
//
// Submodules are decoded but not appraised; pass the claims to an
// Appraiser with a SubmodPolicy for that.
func VerifyToken(ctx context.Context, data []byte, opts VerifyOptions) (*Token, error) {
	return verifyToken(ctx, data, opts, 0)
}

func verifyToken(ctx context.Context, data []byte, opts VerifyOptions, depth int) (*Token, error) {
	inner, tagged, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	if opts.RequireTag && depth == 0 && !tagged {
		return nil, malformed("CWT tag 61 required")
	}
	msg, err := cose.UnmarshalSign1With(inner, tokenDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	nestedCty, err := checkTokenTypes(&msg.Protected, &msg.Unprotected)
	if err != nil {
		return nil, err
	}
	if opts.Keys == nil {
		return nil, fmt.Errorf("%w: no KeyResolver configured", cwt.ErrKeyResolution)
	}
	var vopts []cose.VerifierOption
	if len(opts.AllowedAlgorithms) > 0 {
		vopts = append(vopts, cose.WithAllowedAlgorithms(opts.AllowedAlgorithms...))
	}
	if err := cose.VerifySign1(ctx, msg, opts.Keys, vopts...); err != nil {
		return nil, err
	}
	tok := &Token{Protected: &msg.Protected, Unprotected: &msg.Unprotected, Tagged: tagged}
	if nestedCty || startsWithTag(msg.Payload) {
		if depth+1 > maxNesting(opts.MaxNesting) {
			return nil, fmt.Errorf("%w: nested token deeper than MaxNesting", cwt.ErrUnexpectedType)
		}
		in, err := verifyToken(ctx, msg.Payload, opts, depth+1)
		if err != nil {
			return nil, err
		}
		tok.Nested, tok.Claims = in, in.Claims
		return tok, nil
	}
	claims, err := DecodeClaims(msg.Payload, opts.Options...)
	if err != nil {
		return nil, err
	}
	if err := checkNotExposed(claims, 0); err != nil {
		return nil, err
	}
	v := opts.Validator
	if v == nil {
		v = cwt.NewValidator()
	}
	if err := v.Validate(&claims.ClaimsSet); err != nil {
		return nil, err
	}
	if err := claims.Validate(); err != nil {
		return nil, err
	}
	tok.Claims = claims
	return tok, nil
}

func maxNesting(n int) int {
	switch {
	case n < 0:
		return 0
	case n == 0:
		return 1
	default:
		return n
	}
}

// startsWithTag reports whether b begins with a CBOR tag head. A claims
// set is a map, so a payload that starts with a tag is a nested token
// (RFC 8392 §7.2 step 6).
func startsWithTag(b []byte) bool {
	h := wire.ParseHead(b)
	return h.N > 0 && h.Major == wire.MajorTag
}

// unwrapCWT strips an optional outer CWT tag 61. RFC 8392 §7.2 step 2:
// a COSE tag must follow it.
func unwrapCWT(data []byte) ([]byte, bool, error) {
	h := wire.ParseHead(data)
	if h.N == 0 || h.Major != wire.MajorTag || h.Arg != cwt.TagCWT {
		return data, false, nil
	}
	inner := data[h.N:]
	ih := wire.ParseHead(inner)
	if ih.N == 0 || ih.Major != wire.MajorTag || !isCOSETag(ih.Arg) {
		return nil, true, malformed("CWT tag 61 must be followed by a COSE tag")
	}
	return inner, true, nil
}

// isCOSETag reports whether t is a COSE message tag (RFC 9052 §2).
func isCOSETag(t uint64) bool {
	switch t {
	case 16, 17, 18, 96, 97, 98:
		return true
	}
	return false
}

// tokenMediaTypes and tokenFormats identify a CWT-encoded EAT in typ or
// cty: application/eat+cwt (RFC 9782 §6.3) or application/cwt.
var (
	tokenMediaTypes = []string{MediaTypeEATCWT, cwt.MediaTypeCWT}
	tokenFormats    = []uint64{uint64(ContentFormatEATCWT), cwt.CoAPContentFormatCWT}
)

func isTokenType(format uint64, mediaType string) bool {
	if mediaType == "" {
		for _, f := range tokenFormats {
			if format == f {
				return true
			}
		}
		return false
	}
	// RFC 9782 §3 allows an eat_profile parameter.
	mt, _, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return false
	}
	for _, t := range tokenMediaTypes {
		if strings.EqualFold(mt, t) {
			return true
		}
	}
	return false
}

// checkTokenTypes applies RFC 9596 typ and RFC 8392 cty rules for an
// EAT. It reports whether cty marks a nested token.
func checkTokenTypes(prot, unprot *cose.Headers) (bool, error) {
	for _, h := range []*cose.Headers{prot, unprot} {
		if f, mt, ok := h.Type(); ok && !isTokenType(f, mt) {
			return false, fmt.Errorf("%w: typ %q/%d is not an EAT", cwt.ErrUnexpectedType, mt, f)
		}
	}
	for _, h := range []*cose.Headers{prot, unprot} {
		if f, mt, ok := h.ContentType(); ok {
			if !isTokenType(f, mt) {
				return false, fmt.Errorf("%w: cty %q/%d", cwt.ErrUnexpectedType, mt, f)
			}
			return true, nil
		}
	}
	return false, nil
}

// checkNotExposed refuses a symmetric cnf key by value in a signed EAT
// (RFC 8747 §3.2), in inline submodules too.
func checkNotExposed(c *Claims, depth int) error {
	if c == nil || depth > maxSubmodDepth {
		return nil
	}
	if cnf := c.Confirmation; cnf != nil && cnf.Key != nil && cnf.Key.KeyType() == cose.KeyTypeSymmetric {
		return &cwt.ClaimError{Key: cwt.IntKey(cwt.ClaimCnf), Err: fmt.Errorf(
			"%w: carry it as an Encrypted_COSE_Key (Confirmation.EncryptedKey)", cwt.ErrSymmetricKeyNotEncrypted)}
	}
	for _, name := range sortedSubmodNames(c.Submods) {
		if err := checkNotExposed(c.Submods[name].Claims, depth+1); err != nil {
			return fmt.Errorf("submods[%q]: %w", name, err)
		}
	}
	return nil
}
