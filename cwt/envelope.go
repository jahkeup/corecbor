// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"fmt"

	"github.com/jahkeup/corecbor/wire"
)

// stripTag removes one outer tag id from data, returning the enclosed
// item's bytes exactly as received and whether the tag was present.
// The bytes are sliced, not re-encoded, so signatures over them stay
// valid.
func stripTag(data []byte, id uint64) ([]byte, bool) {
	h := wire.ParseHead(data)
	if h.N == 0 || h.Major != wire.MajorTag || h.AI > wire.AI8Bytes || h.Arg != id {
		return data, false
	}
	return data[h.N:], true
}

// unwrapCWT strips an optional outer CWT tag 61 (RFC 8392 §6). RFC 8392
// §7.2 step 2: one of the COSE tags must follow it, so a second tag 61
// or an untagged COSE message inside it is malformed.
func unwrapCWT(data []byte) ([]byte, bool, error) {
	inner, tagged := stripTag(data, TagCWT)
	if tagged {
		if _, again := stripTag(inner, TagCWT); again {
			return nil, true, fmt.Errorf("%w: nested CWT tag 61", ErrMalformedClaims)
		}
		if h := wire.ParseHead(inner); h.N == 0 || h.Major != wire.MajorTag || !isCOSETag(h.Arg) {
			return nil, true, fmt.Errorf("%w: CWT tag 61 must be followed by a COSE tag", ErrMalformedClaims)
		}
	}
	return inner, tagged, nil
}

// isCOSETag reports whether t is a COSE message tag (RFC 9052 §2).
func isCOSETag(t uint64) bool {
	switch t {
	case 16, 17, 18, 96, 97, 98:
		return true
	}
	return false
}

// startsWithTag reports whether b begins with a CBOR tag. A claims set
// is a map, so such a payload is a nested CWT (RFC 8392 §7.2 step 6).
func startsWithTag(b []byte) bool {
	h := wire.ParseHead(b)
	return h.N > 0 && h.Major == wire.MajorTag
}
