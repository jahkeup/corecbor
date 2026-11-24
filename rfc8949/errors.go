// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"fmt"
	"strconv"

	"github.com/jahkeup/corecbor/cbor"

	"github.com/jahkeup/corecbor/internal/decerr"
)

// Decoder errors are *cbor.DecodeError values built here, so every one
// carries its offset while keeping the v0.2.2 message
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

// withPath prefixes seg onto the Path of err when it is a DecodeError.
func withPath(err error, seg string) error {
	if de, ok := err.(*decerr.Error); ok {
		de.Path = seg + de.Path
	}
	return err
}

// indexPath records array element i on err's path when ErrorPath is
// set. Only called once an error has occurred.
func indexPath(err error, opts DecodeOpts, i int) error {
	if !opts.ErrorPath {
		return err
	}
	return withPath(err, "["+strconv.Itoa(i)+"]")
}

// keyPath records map member k on err's path when ErrorPath is set,
// in RFC 9535 form: .name for identifier-like text keys, ["text"]
// for other text, [n] for integers, and [?] for anything else.
func keyPath(err error, opts DecodeOpts, k cbor.Value) error {
	if !opts.ErrorPath {
		return err
	}
	var seg string
	switch k.Kind {
	case cbor.KindText:
		if isIdent(k.Str) {
			seg = "." + k.Str
		} else {
			seg = "[" + strconv.Quote(k.Str) + "]"
		}
	case cbor.KindUint:
		seg = "[" + strconv.FormatUint(k.Num, 10) + "]"
	case cbor.KindNegInt:
		if k.Num < 1<<63 {
			seg = "[" + strconv.FormatInt(-1-int64(k.Num), 10) + "]"
		} else {
			seg = "[-1-" + strconv.FormatUint(k.Num, 10) + "]"
		}
	default:
		seg = "[?]"
	}
	return withPath(err, seg)
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z':
		case i > 0 && '0' <= r && r <= '9':
		default:
			return false
		}
	}
	return true
}
