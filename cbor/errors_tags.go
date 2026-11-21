// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "errors"

// Tag helper sentinels (proposal 026).
var (
	// ErrMalformedTag indicates a tagged value whose tag number, inner
	// kind or shape doesn't match what a tag helper expects (for
	// example a tag 37 UUID that isn't 16 bytes), or a form the helper
	// doesn't support.
	ErrMalformedTag = errors.New("cbor: malformed tagged value")

	// ErrNonCanonicalTag indicates a tagged value that is well-formed
	// but violates a canonical-form MUST of the tag's RFC (for example
	// an RFC 9164 prefix with host bits or trailing zero bytes, or an
	// RFC 9090 OID arc with a leading 0x80 byte).
	ErrNonCanonicalTag = errors.New("cbor: tagged value not in canonical form")
)
