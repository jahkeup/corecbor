// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package decerr defines the decoder's structured error type. It is
// re-exported as cbor.DecodeError (and corecbor.DecodeError); the
// constructors here are internal so the formatting fields that keep
// messages byte-identical to v0.2.2 can't be set from outside the
// module.
package decerr

import "strconv"

// Error is the concrete type of every error the decoder returns for
// malformed or rejected input. It always wraps one sentinel, so
// errors.Is keeps working through Unwrap.
type Error struct {
	// Offset is the byte offset in the input of the offending item's
	// head (or of the first trailing byte, for trailing-bytes errors).
	Offset int
	// Path locates the offending item, e.g. "$[2].foo". It is set only
	// when the decoder was built with WithErrorPath.
	Path string
	// Err is the sentinel, possibly further wrapped.
	Err error

	detail string // appended after "at offset N"
	text   string // full message, overriding the standard form
}

// Error returns "<sentinel> at offset N<detail>", or the message
// recorded at construction, followed by " (path)" when Path is set.
func (e *Error) Error() string {
	var s string
	if e.text != "" {
		s = e.text
	} else {
		s = e.Err.Error() + " at offset " + strconv.Itoa(e.Offset) + e.detail
	}
	if e.Path != "" {
		s += " (" + e.Path + ")"
	}
	return s
}

// Unwrap returns the wrapped sentinel.
func (e *Error) Unwrap() error { return e.Err }

// New returns an error formatted "<err> at offset <off>".
func New(err error, off int) *Error {
	return &Error{Offset: off, Err: err}
}

// Detail returns an error formatted "<err> at offset <off><detail>";
// detail normally starts with ": ".
func Detail(err error, off int, detail string) *Error {
	return &Error{Offset: off, Err: err, detail: detail}
}

// Text returns an error whose message is exactly text, for sites whose
// v0.2.2 message didn't follow the standard form.
func Text(err error, off int, text string) *Error {
	return &Error{Offset: off, Err: err, text: text}
}
