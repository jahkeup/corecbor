// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/internal/asreceived"
	"github.com/jahkeup/corecbor/wire"
)

// DetachedBundle is a CBOR-encoded detached EAT bundle (RFC 9711 §5):
// a main token carrying detached submodule digests, plus the detached
// claims sets themselves, keyed by submodule name.
type DetachedBundle struct {
	// Token is the main token: CBOR token bytes (e.g. a tagged
	// COSE_Sign1). For a JSON main token, JSONToken is set instead.
	Token     []byte
	JSONToken []byte
	// Detached holds each detached Claims-Set's encoded bytes, exactly as
	// they appear in the bundle, ready for digest comparison and
	// DecodeClaims.
	Detached map[string][]byte
}

// DecodeDetachedBundle decodes a detached EAT bundle, tagged (602) or
// untagged, and checks its shape (RFC 9711 §5): a CBOR main token is one
// tagged data item and not itself a bundle; each detached claims set is
// a byte string wrapping one CBOR map. The main token is not verified
// here; verify it (VerifyToken), then appraise its claims with
// Appraiser.SubmodDetached set to the bundle's CheckDetached.
func DecodeDetachedBundle(data []byte) (*DetachedBundle, error) {
	v, err := corecbor.NewDecoder(
		corecbor.WithoutInternalArena(),
		corecbor.RejectDuplicateMapKeys(),
		corecbor.WithMemoryBudget(decodeBudget),
	).Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	if v.Kind == corecbor.KindTag {
		if v.TagID() != TagDetachedEATBundle {
			return nil, malformed("detached EAT bundle: unexpected tag %d", v.TagID())
		}
		v = v.TagInner()
	}
	items := v.Array()
	if v.Kind != corecbor.KindArray || len(items) != 2 {
		return nil, malformed("detached EAT bundle must be [main-token, detached-claims-sets]")
	}
	b := &DetachedBundle{}
	switch items[0].Kind {
	case corecbor.KindBytes:
		tok := items[0].BytesVal()
		if err := checkNestedToken(tok); err != nil {
			return nil, fmt.Errorf("detached EAT bundle main token: %w", err)
		}
		if h := wire.ParseHead(tok); h.Arg == TagDetachedEATBundle {
			// RFC 9711 §5: the main token MUST NOT be a detached bundle.
			return nil, malformed("detached EAT bundle main token is itself a detached EAT bundle")
		}
		b.Token = tok
	case corecbor.KindText:
		b.JSONToken = []byte(items[0].TextVal())
	default:
		return nil, malformed("detached EAT bundle main token must be bytes or text")
	}
	sets := items[1]
	if sets.Kind != corecbor.KindMap || len(sets.Map()) == 0 {
		return nil, malformed("detached EAT bundle needs a non-empty map of detached claims sets")
	}
	b.Detached = make(map[string][]byte, len(sets.Map()))
	for _, e := range sets.Map() {
		if e.Key.Kind != corecbor.KindText {
			return nil, malformed("detached claims set names must be text")
		}
		name := e.Key.TextVal()
		// RFC 9711 §5: in a CBOR bundle each set is a byte-string-wrapped
		// CBOR Claims-Set (cbor-wrapped-claims-set); the base64 text form
		// belongs to JSON bundles.
		if e.Value.Kind != corecbor.KindBytes {
			return nil, malformed("detached claims set %q must be a byte string in a CBOR bundle", name)
		}
		set := e.Value.BytesVal()
		if h := wire.ParseHead(set); h.N == 0 || h.Major != wire.MajorMap || !asreceived.OneItem(set) {
			return nil, malformed("detached claims set %q must wrap one CBOR map", name)
		}
		b.Detached[name] = set
	}
	return b, nil
}

// CheckDetached checks a detached submodule digest against the bundle:
// d.Digest must be the digest, under d's COSE hash algorithm, of the
// detached claims set named name, exactly as carried in the bundle
// (RFC 9711 §4.2.18.2). It has the signature of
// Appraiser.SubmodDetached; pass b.CheckDetached there after verifying
// b.Token. SHA-256 (-16), SHA-384 (-43), SHA-512 (-44) and SHA-512/256
// (-17), or their names, are accepted; truncated SHA-256/64 (-15) is
// not. A missing set is ErrSubmodUnverified, a mismatch
// cose.ErrVerification, another algorithm cose.ErrUnsupportedAlgorithm.
func (b *DetachedBundle) CheckDetached(_ context.Context, name string, d DetachedDigest) error {
	set, ok := b.Detached[name]
	if !ok {
		return fmt.Errorf("%w: no detached claims set %q in the bundle", ErrSubmodUnverified, name)
	}
	h, err := digestHash(d)
	if err != nil {
		return err
	}
	h.Write(set)
	if subtle.ConstantTimeCompare(h.Sum(nil), d.Digest) != 1 {
		return fmt.Errorf("%w: detached claims set %q does not match its digest", cose.ErrVerification, name)
	}
	return nil
}

// digestHash returns the hash for a Detached-Submodule-Digest's COSE
// algorithm (integer or text form).
func digestHash(d DetachedDigest) (hash.Hash, error) {
	switch {
	case d.Alg == -16 || (d.Alg == 0 && d.AlgName == "SHA-256"):
		return sha256.New(), nil
	case d.Alg == -43 || (d.Alg == 0 && d.AlgName == "SHA-384"):
		return sha512.New384(), nil
	case d.Alg == -44 || (d.Alg == 0 && d.AlgName == "SHA-512"):
		return sha512.New(), nil
	case d.Alg == -17 || (d.Alg == 0 && d.AlgName == "SHA-512/256"):
		return sha512.New512_256(), nil
	}
	return nil, fmt.Errorf("%w: detached digest algorithm %d %q", cose.ErrUnsupportedAlgorithm, d.Alg, d.AlgName)
}
