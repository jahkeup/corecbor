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

// unwrapCWT strips an optional outer CWT tag 61 (RFC 8392 §6). A second
// tag 61 directly inside the first is malformed.
func unwrapCWT(data []byte) ([]byte, bool, error) {
	inner, tagged := stripTag(data, TagCWT)
	if tagged {
		if _, again := stripTag(inner, TagCWT); again {
			return nil, true, fmt.Errorf("%w: nested CWT tag 61", ErrMalformedClaims)
		}
	}
	return inner, tagged, nil
}
