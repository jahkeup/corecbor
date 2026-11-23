// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/internal/asreceived"
	"github.com/jahkeup/corecbor/internal/rawvalue"
)

// Registered claim keys (IANA "CBOR Web Token (CWT) Claims").
const (
	ClaimIss        int64 = 1
	ClaimSub        int64 = 2
	ClaimAud        int64 = 3
	ClaimExp        int64 = 4
	ClaimNbf        int64 = 5
	ClaimIat        int64 = 6
	ClaimCti        int64 = 7
	ClaimCnf        int64 = 8  // RFC 8747
	ClaimScope      int64 = 9  // RFC 9200 §5.10.1
	ClaimNonce      int64 = 10 // RFC 9711
	ClaimACEProfile int64 = 38 // RFC 9200
	ClaimCNonce     int64 = 39 // RFC 9200
	ClaimExi        int64 = 40 // RFC 9200
)

const (
	// TagCWT is the CWT CBOR tag (RFC 8392 §6). It may wrap the COSE
	// message carrying the claims.
	TagCWT uint64 = 61

	// TagUCCS is the Unprotected CWT Claims Set tag (RFC 9781).
	TagUCCS uint64 = 601

	// HeaderLabelCWTClaims is the COSE header carrying a CWT Claims Set
	// (RFC 9597).
	HeaderLabelCWTClaims int64 = 15
)

// ClaimKey is a CWT claim label: an integer or a text string
// (RFC 8392 §4). It is comparable and safe to use as a map key.
//
// Raw is non-empty only for labels that are neither an int64 nor text
// (for example a byte string, or an integer outside the int64 range).
// Such labels are malformed per RFC 8392 §4 but are kept, as their
// Core Deterministic encoding, so decoding never loses a claim.
type ClaimKey struct {
	Int    int64
	Text   string
	IsText bool
	Raw    string
}

// IntKey returns the integer claim key n.
func IntKey(n int64) ClaimKey { return ClaimKey{Int: n} }

// TextKey returns the text claim key s.
func TextKey(s string) ClaimKey { return ClaimKey{Text: s, IsText: true} }

// String renders the key for error messages.
func (k ClaimKey) String() string {
	switch {
	case k.Raw != "":
		return "h'" + hex.EncodeToString([]byte(k.Raw)) + "'"
	case k.IsText:
		return strconv.Quote(k.Text)
	default:
		return strconv.FormatInt(k.Int, 10)
	}
}

// receivedKey returns a key asreceived.IntegerBignum matched as a Raw ClaimKey
// in its received form. Tags 2 and 3 have one-byte heads (0xc2, 0xc3)
// and a byte string encodes as received, so this is the key's original
// encoding (normalizing it would yield the integer it collides with).
func receivedKey(k corecbor.Value) ClaimKey {
	enc, err := keyEncoder.Encode([]byte{0xc0 | byte(k.TagID())}, k.TagInner())
	if err != nil {
		return ClaimKey{Raw: "\x00invalid"}
	}
	return ClaimKey{Raw: string(enc)}
}

// ambiguousKeyErr is the error for a key asreceived.IntegerBignum reports.
func ambiguousKeyErr(k corecbor.Value) error {
	return &ClaimError{Key: receivedKey(k), Err: fmt.Errorf("%w: %w: bignum with an integer value", ErrMalformedClaims, ErrAmbiguousClaimKey)}
}

// claimKeyOf maps a decoded map key to a ClaimKey. Integers outside
// the int64 range do not wrap onto other keys; they become Raw.
func claimKeyOf(v corecbor.Value) ClaimKey {
	switch v.Kind {
	case corecbor.KindUint, corecbor.KindNegInt:
		if n, err := v.Int64(); err == nil {
			return IntKey(n)
		}
	case corecbor.KindText:
		return TextKey(v.TextVal())
	}
	enc, err := keyEncoder.Encode(nil, v)
	if err != nil {
		// Only reachable for values that can't be encoded at all; keep
		// a stable, distinct label rather than dropping the claim.
		return ClaimKey{Raw: "\x00invalid"}
	}
	return ClaimKey{Raw: string(enc)}
}

// receivedValue returns k as written for ReceivedClaims: a Raw key is
// spliced verbatim instead of decoded and re-encoded.
func (k ClaimKey) receivedValue() (corecbor.Value, error) {
	if k.Raw == "" {
		return k.value()
	}
	if !asreceived.OneItem([]byte(k.Raw)) {
		return corecbor.Value{}, fmt.Errorf("%w: Raw is not one CBOR data item", ErrMalformedClaims)
	}
	return rawvalue.Make([]byte(k.Raw)), nil
}

// value returns the CBOR form of k.
func (k ClaimKey) value() (corecbor.Value, error) {
	switch {
	case k.Raw != "":
		return keyDecoder().Decode([]byte(k.Raw))
	case k.IsText:
		return corecbor.Text(k.Text), nil
	default:
		return intValue(k.Int), nil
	}
}

func intValue(n int64) corecbor.Value {
	if n >= 0 {
		return corecbor.Uint(uint64(n))
	}
	return corecbor.NegInt(uint64(-1 - n))
}

// keyEncoder encodes claim keys and values for comparison and Raw
// labels. It is shared across goroutines, so it comes from NewShared.
var keyEncoder = corecbor.NewShared(corecbor.ModeCoreDeterministic, corecbor.AllowInvalidUTF8(), corecbor.AllowNonFiniteFloats())

func keyDecoder() *corecbor.Decoder { return corecbor.NewDecoder(corecbor.WithoutInternalArena()) }
