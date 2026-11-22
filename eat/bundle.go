// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"fmt"

	"github.com/jahkeup/corecbor"
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
// untagged. The main token is not verified here; verify it, then check
// each detached digest against Detached (for example from an
// Appraiser.SubmodDetached callback).
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
		b.Token = items[0].BytesVal()
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
		switch e.Value.Kind {
		case corecbor.KindBytes:
			b.Detached[e.Key.TextVal()] = e.Value.BytesVal()
		case corecbor.KindText:
			b.Detached[e.Key.TextVal()] = []byte(e.Value.TextVal()) // json-wrapped-claims-set
		default:
			return nil, malformed("detached claims set %q must be bytes", e.Key.TextVal())
		}
	}
	return b, nil
}
