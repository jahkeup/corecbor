// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package scitt builds and checks SCITT signed statements and
// transparent statements (RFC 9943).
//
// A signed statement is a tagged COSE_Sign1 whose protected bucket
// carries CWT Claims (label 15, RFC 9597) with at least iss and sub,
// and an issuer key identifier: kid, or x5t/x5chain (RFC 9360). Its
// payload may be the statement itself or, with a COSE Hash Envelope
// (RFC 9995), its digest; either may be detached. A transparent
// statement is a signed statement with one or more COSE Receipts
// (RFC 9942) attached under label 394.
//
// The data structures are implemented here; the SCITT registration
// API (draft-ietf-scitt-scrapi) and log-specific receipt profiles are
// not.
package scitt

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
	"github.com/jahkeup/corecbor/wire"
)

// MaxIssuerLength is the longest iss RFC 9943 §6 allows when the issuer
// is identified by an X.509 certificate.
const MaxIssuerLength = 8192

// COSE header labels used by signed statements.
const (
	headerLabelX5Chain int64 = 33 // RFC 9360
	headerLabelX5T     int64 = 34 // RFC 9360
)

// ErrInvalidStatement is returned for a message that isn't a valid
// signed statement. It wraps cose.ErrMalformed.
var ErrInvalidStatement = fmt.Errorf("scitt: invalid signed statement: %w", cose.ErrMalformed)

// Statement is a parsed SCITT signed statement.
type Statement struct {
	Msg    *cose.Sign1
	Claims *cwt.ClaimsSet // from protected label 15
	// Type is the typ header (label 16, RFC 9596): a uint64 content
	// format or a media-type string; nil when absent.
	Type any
	// HashEnvelope is set when the statement is a COSE Hash Envelope
	// (protected label 258): its payload is a digest of the statement.
	HashEnvelope *cose.HashEnvelope
}

// IssueOptions configures Issue.
type IssueOptions struct {
	// Issuer and Subject are the CWT iss and sub claims. Both are
	// required (they override any value in Claims).
	Issuer, Subject string
	// Claims, if set, supplies further claims (for example iat) for the
	// protected CWT Claims header. It is not modified.
	Claims *cwt.ClaimsSet
	// ContentType is the payload's content type (label 3): a uint64
	// content format or a media-type string. With HashEnvelope, use the
	// envelope's PreimageContentType instead (RFC 9995 forbids label 3).
	ContentType any
	// Type is the typ header (label 16, RFC 9596).
	Type any
	// HashEnvelope, if set, signs the digest of the payload instead of
	// the payload (RFC 9995, RFC 9943 §6.2).
	HashEnvelope *cose.HashEnvelope
	// Detached leaves the signed payload (or digest) out of the message.
	Detached bool
	// KeyID is the issuer's kid (label 4). RFC 9943 requires a kid
	// unless X5Chain or X5T identifies the issuer.
	KeyID []byte
	// X5Chain is the issuer's certificate chain, leaf first, placed in
	// the protected bucket (label 33).
	X5Chain [][]byte
	// X5T is the hash of the issuer's certificate (label 34).
	X5T *cose.CertHash
}

// Issue signs payload as a signed statement with s. The issuer
// identity, claims and key identifiers go in the protected bucket,
// merged with s's own headers (which may already carry kid or x5chain).
// The result is checked against RFC 9943 §6 before it is returned.
func Issue(ctx context.Context, s *cose.Signer, payload []byte, o IssueOptions) (*Statement, error) {
	claims := &cwt.ClaimsSet{}
	if o.Claims != nil {
		c := *o.Claims
		claims = &c
	}
	claims.Issuer, claims.Subject = o.Issuer, o.Subject
	if claims.Issuer == "" || claims.Subject == "" {
		return nil, fmt.Errorf("%w: iss and sub are required", ErrInvalidStatement)
	}
	msg := &cose.Sign1{}
	if err := cwt.SetClaimsHeader(&msg.Protected, claims); err != nil {
		return nil, err
	}
	if o.ContentType != nil {
		if o.HashEnvelope != nil {
			return nil, fmt.Errorf("%w: content type (label 3) is not allowed in a hash envelope; use HashEnvelope.PreimageContentType", ErrInvalidStatement)
		}
		if err := msg.Protected.SetContentType(o.ContentType); err != nil {
			return nil, err
		}
	}
	if o.Type != nil {
		if err := msg.Protected.SetType(o.Type); err != nil {
			return nil, err
		}
	}
	if o.KeyID != nil {
		msg.Protected.SetKeyID(o.KeyID)
	}
	if len(o.X5Chain) > 0 {
		if err := msg.Protected.SetX5Chain(o.X5Chain...); err != nil {
			return nil, err
		}
	}
	if o.X5T != nil {
		if err := msg.Protected.SetX5T(o.X5T.Alg, o.X5T.Hash); err != nil {
			return nil, err
		}
	}

	if o.HashEnvelope != nil {
		digest, err := o.HashEnvelope.Hash(payload)
		if err != nil {
			return nil, err
		}
		if err := s.SignHashEnvelopeMessage(ctx, msg, digest, *o.HashEnvelope, o.Detached); err != nil {
			return nil, err
		}
	} else {
		if payload == nil {
			payload = []byte{}
		}
		msg.Payload = payload
		if err := s.Sign1Context(ctx, msg); err != nil {
			return nil, err
		}
		if o.Detached {
			msg.Payload = nil
		}
	}
	return checkStatement(msg)
}

// ParseStatement decodes a signed (or transparent) statement with
// cose.RecommendedDecodeLimits and checks it against RFC 9943 §6: a
// tagged COSE_Sign1, CWT Claims with text iss and sub in the protected
// bucket only, and a protected kid unless x5t or x5chain is protected
// (in which case iss must be a URI-conformant StringOrURI of at most
// 8192 characters). It does not verify signatures.
func ParseStatement(data []byte) (*Statement, error) {
	if !isTaggedSign1(data) {
		return nil, fmt.Errorf("%w: not a tagged COSE_Sign1 (tag 18)", ErrInvalidStatement)
	}
	msg, err := cose.UnmarshalSign1With(data, cose.RecommendedDecodeLimits)
	if err != nil {
		return nil, err
	}
	return checkStatement(msg)
}

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

func checkStatement(msg *cose.Sign1) (*Statement, error) {
	if msg.Unprotected.Get(cwt.HeaderLabelCWTClaims) != nil {
		return nil, fmt.Errorf("%w: CWT Claims (label 15) must be protected", ErrInvalidStatement)
	}
	claims, ok, err := cwt.ClaimsFromHeaders(&msg.Protected)
	if err != nil {
		return nil, fmt.Errorf("%w: CWT Claims: %w", ErrInvalidStatement, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: no CWT Claims (label 15) in the protected bucket", ErrInvalidStatement)
	}
	if claims.Issuer == "" || claims.Subject == "" {
		return nil, fmt.Errorf("%w: CWT Claims must carry iss and sub", ErrInvalidStatement)
	}
	if err := checkIssuerKey(msg, claims); err != nil {
		return nil, err
	}
	st := &Statement{Msg: msg, Claims: claims}
	if format, mediaType, ok := msg.Protected.Type(); ok {
		if mediaType != "" {
			st.Type = mediaType
		} else {
			st.Type = format
		}
	}
	if msg.Protected.Get(cose.HeaderPayloadHashAlg) != nil {
		env, err := cose.HashEnvelopeFrom(msg)
		if err != nil {
			return nil, fmt.Errorf("%w: hash envelope: %w", ErrInvalidStatement, err)
		}
		st.HashEnvelope = &env
	}
	return st, nil
}

// checkIssuerKey applies RFC 9943 §6's key identification rule, which
// covers signed statements and receipts alike: a protected kid unless
// x5t or x5chain is protected, in which case iss must suit an X.509
// issuer.
func checkIssuerKey(msg *cose.Sign1, claims *cwt.ClaimsSet) error {
	if msg.Protected.Get(headerLabelX5Chain) != nil || msg.Protected.Get(headerLabelX5T) != nil {
		return checkX509Issuer(claims.Issuer)
	}
	if len(msg.Protected.KeyID()) == 0 {
		return fmt.Errorf("%w: a protected kid is required when neither x5t nor x5chain is protected", ErrInvalidStatement)
	}
	return nil
}

// checkX509Issuer applies RFC 9943 §6 to iss when the issuer is an
// X.509 certificate: 1 to 8192 characters, and a StringOrURI (RFC 8392
// §2), so a value containing ':' must be an absolute URI.
func checkX509Issuer(iss string) error {
	if n := len([]rune(iss)); n < 1 || n > MaxIssuerLength {
		return fmt.Errorf("%w: iss is %d characters, want 1 to %d", ErrInvalidStatement, n, MaxIssuerLength)
	}
	if strings.Contains(iss, ":") {
		u, err := url.Parse(iss)
		if err != nil || u.Scheme == "" {
			return fmt.Errorf("%w: iss %q contains ':' but is not a URI", ErrInvalidStatement, iss)
		}
	}
	return nil
}

// Entry returns the bytes a transparency service registers for stmt:
// the statement with an empty unprotected bucket (RFC 9943 §6: the
// unprotected header MUST be set to an empty map before the statement
// is included in a Statement Sequence), encoded as a tagged COSE_Sign1.
// The protected bytes, payload (nil when detached) and signature are
// kept as they are. This is the entry RFC9162_SHA256 receipts prove
// inclusion of here; a log profile that defines a different leaf needs
// receipt.Receipt.VerifyInclusionHash instead.
func Entry(stmt *cose.Sign1) ([]byte, error) {
	e := *stmt
	e.Unprotected = cose.Headers{}
	return cose.MarshalSign1(&e)
}

// ReceiptHeaders returns protected headers for a transparency service's
// receipt: RFC 9943 §6 requires CWT Claims with iss (the service) and
// sub in a receipt's protected bucket too.
func ReceiptHeaders(issuer, subject string) (cose.Headers, error) {
	if issuer == "" || subject == "" {
		return cose.Headers{}, fmt.Errorf("%w: receipt iss and sub are required", ErrInvalidStatement)
	}
	var h cose.Headers
	if err := cwt.SetClaimsHeader(&h, &cwt.ClaimsSet{Issuer: issuer, Subject: subject}); err != nil {
		return cose.Headers{}, err
	}
	return h, nil
}
