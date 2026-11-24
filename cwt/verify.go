// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"context"
	"fmt"
	"mime"
	"slices"
	"strings"

	"github.com/jahkeup/corecbor/cose"
)

// MediaTypeCWT is the CWT media type (RFC 8392 §9.3); CoAPContentFormatCWT
// is its CoAP Content-Format (RFC 8392 §9.4).
const (
	MediaTypeCWT         = "application/cwt"
	CoAPContentFormatCWT = 61
)

// VerifyOptions configures VerifyToken, VerifyMACToken and OpenToken.
// The zero value verifies with no key (VerifyToken returns
// ErrKeyResolution) and validates with NewValidator().
type VerifyOptions struct {
	// Keys resolves the verification key for VerifyToken (proposal 028).
	// Unused by VerifyMACToken and OpenToken, which take the key.
	Keys cose.KeyResolver

	// Validator validates the decoded claims. nil means NewValidator().
	Validator *Validator

	// RequireTag requires the outer CWT tag 61 (RFC 8392 §6).
	RequireTag bool

	// AllowedAlgorithms restricts the protected alg. For VerifyToken it
	// is passed to cose.WithAllowedAlgorithms (empty: the resolved key
	// decides). For VerifyMACToken and OpenToken, whose keys carry no
	// algorithm, an empty list means the full-length HMACs (5, 6, 7) or
	// AES-GCM (1, 2, 3) respectively; list AlgHMAC256_64 explicitly to
	// accept a truncated MAC.
	AllowedAlgorithms []cose.Algorithm

	// MaxNesting bounds nested CWTs: a payload that begins with a CBOR
	// tag (RFC 8392 §7.2 step 6), or cty 61 / "application/cwt". 0
	// means 1; negative forbids nesting. Nesting is supported for
	// COSE_Sign1 inside COSE_Sign1; VerifyMACToken and OpenToken
	// reject a nested payload with ErrUnexpectedType.
	MaxNesting int

	// Decode adjusts claims decoding.
	Decode DecodeOptions

	// Types, when non-empty, lists the typ header values (RFC 9596)
	// accepted instead of the default application/cwt and 61: each a
	// media-type string (compared case-insensitively, parameters
	// ignored) or a uint64 CoAP Content-Format, as for
	// cose.Headers.SetType. List MediaTypeCWT too to keep accepting
	// it. For example, an EAT-aware caller lists
	// "application/eat+cwt" and 263.
	Types []any

	// RequireType requires a typ header (explicit typing, RFC 8725
	// §3.11, RFC 9596), so a token of another kind signed by the same
	// key can't be substituted. Without it a token with no typ passes.
	RequireType bool
}

// Token is a verified CWT and its COSE envelope.
type Token struct {
	Protected   *cose.Headers
	Unprotected *cose.Headers
	Claims      *ClaimsSet
	Tagged      bool   // outer tag 61 was present
	Nested      *Token // the inner token, for a nested CWT; Claims are its claims
}

var (
	defaultMACAlgs     = []cose.Algorithm{cose.AlgHMAC256, cose.AlgHMAC384, cose.AlgHMAC512}
	defaultEncryptAlgs = []cose.Algorithm{cose.AlgA128GCM, cose.AlgA192GCM, cose.AlgA256GCM}
)

// VerifyToken parses data (optionally tag-61 wrapped; COSE_Sign1 tagged
// or untagged), resolves the key through opts.Keys, verifies the
// signature, checks typ and cty when present, decodes the claims
// strictly and validates them. It is the recommended entry point for
// signed CWTs.
func VerifyToken(ctx context.Context, data []byte, opts VerifyOptions) (*Token, error) {
	return verifySigned(ctx, data, opts, 0)
}

func verifySigned(ctx context.Context, data []byte, opts VerifyOptions, depth int) (*Token, error) {
	inner, tagged, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	if opts.RequireTag && depth == 0 && !tagged {
		return nil, fmt.Errorf("%w: CWT tag 61 required", ErrMalformedClaims)
	}
	msg, err := cose.UnmarshalSign1With(inner, cose.RecommendedDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	nested, err := checkContentTypes(&msg.Protected, &msg.Unprotected, opts, depth == 0)
	if err != nil {
		return nil, err
	}
	if opts.Keys == nil {
		return nil, fmt.Errorf("%w: no KeyResolver configured", ErrKeyResolution)
	}
	var vopts []cose.VerifierOption
	if len(opts.AllowedAlgorithms) > 0 {
		vopts = append(vopts, cose.WithAllowedAlgorithms(opts.AllowedAlgorithms...))
	}
	if err := cose.VerifySign1(ctx, msg, resolverWithErr(opts.Keys), vopts...); err != nil {
		return nil, err
	}
	tok := &Token{Protected: &msg.Protected, Unprotected: &msg.Unprotected, Tagged: tagged}
	if nested || startsWithTag(msg.Payload) {
		if depth+1 > maxNesting(opts) {
			return nil, fmt.Errorf("%w: nested CWT deeper than MaxNesting", ErrUnexpectedType)
		}
		innerTok, err := verifySigned(ctx, msg.Payload, opts, depth+1)
		if err != nil {
			return nil, err
		}
		tok.Nested, tok.Claims = innerTok, innerTok.Claims
		return tok, nil
	}
	if tok.Claims, err = decodeAndValidate(msg.Payload, opts, false); err != nil {
		return nil, err
	}
	return tok, nil
}

// VerifyMACToken is the COSE_Mac0 counterpart of VerifyToken: it
// verifies the MAC with key and validates the claims. The algorithm is
// the protected alg, which must be in opts.AllowedAlgorithms (by
// default the full-length HMACs).
func VerifyMACToken(ctx context.Context, data []byte, key []byte, opts VerifyOptions) (*Token, error) {
	inner, tagged, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	if opts.RequireTag && !tagged {
		return nil, fmt.Errorf("%w: CWT tag 61 required", ErrMalformedClaims)
	}
	msg, err := cose.UnmarshalMac0With(inner, cose.RecommendedDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	if err := checkNotNested(&msg.Protected, &msg.Unprotected, opts); err != nil {
		return nil, err
	}
	alg, err := protectedAlg(&msg.Protected, opts.AllowedAlgorithms, defaultMACAlgs)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cose.VerifyMAC0(msg, key, alg, cose.WithMACAlgorithms(alg)); err != nil {
		return nil, err
	}
	claims, err := decodeNotNested(msg.Payload, opts, false)
	if err != nil {
		return nil, err
	}
	return &Token{Protected: &msg.Protected, Unprotected: &msg.Unprotected, Claims: claims, Tagged: tagged}, nil
}

// OpenToken is the COSE_Encrypt0 counterpart of VerifyToken: it
// decrypts with key, taking the IV from the IV header (label 5, as Seal
// writes it), and validates the claims. The algorithm is the protected
// alg, which must be in opts.AllowedAlgorithms (by default AES-GCM).
func OpenToken(ctx context.Context, data []byte, key []byte, opts VerifyOptions) (*Token, error) {
	inner, tagged, err := unwrapCWT(data)
	if err != nil {
		return nil, err
	}
	if opts.RequireTag && !tagged {
		return nil, fmt.Errorf("%w: CWT tag 61 required", ErrMalformedClaims)
	}
	msg, err := cose.UnmarshalEncrypt0With(inner, cose.RecommendedDecodeLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	if err := checkNotNested(&msg.Protected, &msg.Unprotected, opts); err != nil {
		return nil, err
	}
	alg, err := protectedAlg(&msg.Protected, opts.AllowedAlgorithms, defaultEncryptAlgs)
	if err != nil {
		return nil, err
	}
	if msg.Unprotected.IV() == nil && msg.Protected.IV() == nil {
		return nil, fmt.Errorf("%w: missing IV header", ErrMalformedClaims)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plaintext, err := cose.Encrypt0Open(msg, key, cose.WithEncryptAlgorithms(alg))
	if err != nil {
		return nil, err
	}
	claims, err := decodeNotNested(plaintext, opts, true)
	if err != nil {
		return nil, err
	}
	return &Token{Protected: &msg.Protected, Unprotected: &msg.Unprotected, Claims: claims, Tagged: tagged}, nil
}

// Seal encrypts claims as a COSE_Encrypt0 CWT with a fresh random IV,
// written to the unprotected IV header (label 5) so OpenToken can
// decrypt without an out-of-band nonce.
func Seal(claims *ClaimsSet, key []byte, alg cose.Algorithm, opts ...cose.EncryptOption) ([]byte, error) {
	payload, err := claims.Encode()
	if err != nil {
		return nil, err
	}
	if !slices.Contains(defaultEncryptAlgs, alg) {
		return nil, fmt.Errorf("%w: %s is not an AES-GCM algorithm", cose.ErrUnsupportedAlgorithm, alg)
	}
	msg, err := cose.Encrypt0Seal(payload, key, alg, opts...)
	if err != nil {
		return nil, err
	}
	return cose.MarshalEncrypt0(msg)
}

// decodeAndValidate decodes and validates the claims. encrypted reports
// whether they arrived encrypted, the only case in which a symmetric
// cnf key by value is acceptable (RFC 8747 §3.2).
func decodeAndValidate(payload []byte, opts VerifyOptions, encrypted bool) (*ClaimsSet, error) {
	var claims *ClaimsSet
	var err error
	if encrypted {
		claims, err = DecodeClaimsSetWith(payload, opts.Decode)
	} else {
		claims, err = decodePlaintextClaims(payload, opts.Decode)
	}
	if err != nil {
		return nil, err
	}
	v := opts.Validator
	if v == nil {
		v = NewValidator()
	}
	if err := v.Validate(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func maxNesting(opts VerifyOptions) int {
	switch {
	case opts.MaxNesting < 0:
		return 0
	case opts.MaxNesting == 0:
		return 1
	default:
		return opts.MaxNesting
	}
}

// protectedAlg returns the protected alg if it is allowed. With no alg
// header and a single allowed algorithm, that algorithm is used.
func protectedAlg(prot *cose.Headers, allowed, defaults []cose.Algorithm) (cose.Algorithm, error) {
	if len(allowed) == 0 {
		allowed = defaults
	}
	alg := prot.Algorithm()
	if alg == 0 {
		if len(allowed) != 1 {
			return 0, fmt.Errorf("%w: missing protected alg", ErrMalformedClaims)
		}
		return allowed[0], nil
	}
	if !slices.Contains(allowed, alg) {
		return 0, fmt.Errorf("%w: alg %d not allowed", cose.ErrAlgorithmMismatch, alg)
	}
	return alg, nil
}

func isCWTType(format uint64, mediaType string) bool {
	return mediaType == MediaTypeCWT || (mediaType == "" && format == CoAPContentFormatCWT)
}

// typeAccepted reports whether a typ value is accepted under opts.Types
// (entries already checked to be string or uint64), or, when that is
// empty, whether it names a CWT.
func typeAccepted(format uint64, mediaType string, opts VerifyOptions) bool {
	if len(opts.Types) == 0 {
		return isCWTType(format, mediaType)
	}
	var mt string
	if mediaType != "" {
		parsed, _, err := mime.ParseMediaType(mediaType)
		if err != nil {
			return false
		}
		mt = parsed
	}
	for _, t := range opts.Types {
		switch want := t.(type) {
		case string:
			if mt != "" && strings.EqualFold(mt, want) {
				return true
			}
		case uint64:
			if mediaType == "" && format == want {
				return true
			}
		}
	}
	return false
}

// checkContentTypes applies RFC 9596 typ (opts.Types, opts.RequireType
// when top is set) and RFC 8392 cty rules. It reports whether cty marks
// a nested CWT.
func checkContentTypes(prot, unprot *cose.Headers, opts VerifyOptions, top bool) (bool, error) {
	for _, t := range opts.Types {
		switch t.(type) {
		case string, uint64:
		default:
			return false, fmt.Errorf("%w: VerifyOptions.Types entry %v (%T) is not a media type or a uint64 content format", ErrUnexpectedType, t, t)
		}
	}
	seen := false
	for _, h := range []*cose.Headers{prot, unprot} {
		f, mt, ok := h.Type()
		if !ok {
			continue
		}
		seen = true
		if !typeAccepted(f, mt, opts) {
			return false, fmt.Errorf("%w: typ %q/%d", ErrUnexpectedType, mt, f)
		}
	}
	if top && opts.RequireType && !seen {
		return false, fmt.Errorf("%w: typ header required", ErrUnexpectedType)
	}
	for _, h := range []*cose.Headers{prot, unprot} {
		if f, mt, ok := h.ContentType(); ok {
			if !isCWTType(f, mt) {
				return false, fmt.Errorf("%w: cty %q/%d", ErrUnexpectedType, mt, f)
			}
			return true, nil
		}
	}
	return false, nil
}

func checkNotNested(prot, unprot *cose.Headers, opts VerifyOptions) error {
	nested, err := checkContentTypes(prot, unprot, opts, true)
	if err != nil {
		return err
	}
	if nested {
		return errNestedUnsupported
	}
	return nil
}

var errNestedUnsupported = fmt.Errorf("%w: nested CWT is supported only for COSE_Sign1", ErrUnexpectedType)

// decodeNotNested is decodeAndValidate for a MAC or encrypted CWT,
// whose payload may not be another CWT (RFC 8392 §7.2 step 6; only
// COSE_Sign1 nesting is supported).
func decodeNotNested(payload []byte, opts VerifyOptions, encrypted bool) (*ClaimsSet, error) {
	if startsWithTag(payload) {
		return nil, errNestedUnsupported
	}
	return decodeAndValidate(payload, opts, encrypted)
}

// resolverWithErr wraps resolver failures in ErrKeyResolution.
func resolverWithErr(r cose.KeyResolver) cose.KeyResolver {
	return cose.KeyResolverFunc(func(ctx context.Context, prot, unprot *cose.Headers) ([]*cose.Key, error) {
		keys, err := r.ResolveKey(ctx, prot, unprot)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrKeyResolution, err)
		}
		return keys, nil
	})
}
