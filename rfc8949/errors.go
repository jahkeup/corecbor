// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"fmt"

	"github.com/jahkeup/corecbor/internal/decerr"
)

// Decoder errors are *cbor.DecodeError values built here, so every one
// carries its offset (proposal 023) while keeping the v0.2.2 message
// text "<sentinel> at offset N[: detail]".

// decodeErr returns "<err> at offset <off>".
func decodeErr(err error, off int) error {
	return decerr.New(err, off)
}

// decodeErrDetail returns "<err> at offset <off><detail>".
func decodeErrDetail(err error, off int, detail string) error {
	return decerr.Detail(err, off, detail)
}

// decodeErrf returns "<err> at offset <off>" followed by the formatted
// detail.
func decodeErrf(err error, off int, format string, args ...any) error {
	return decerr.Detail(err, off, fmt.Sprintf(format, args...))
}
