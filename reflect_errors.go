// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/jahkeup/corecbor/cbor"
)

// UnmarshalTypeError describes a CBOR value that could not be stored in
// a Go value of a specific type. It wraps ErrTypeMismatch, ErrOverflow
// or ErrUnsupportedType, so errors.Is matches those sentinels.
type UnmarshalTypeError struct {
	CBORKind cbor.Kind    // kind of the CBOR value
	GoType   reflect.Type // type of the Go value it couldn't be stored in
	Field    string       // dotted Go field path, e.g. "Header.Alg"; "" outside structs
	Err      error        // ErrTypeMismatch, ErrOverflow or ErrUnsupportedType

	msg string // message text, unchanged from v0.2.2
}

// Error returns the error message. Its text is the same as v0.2.2's
// for each case; Field is not included.
func (e *UnmarshalTypeError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return fmt.Sprintf("cbor: cannot decode kind %d into Go type %s", e.CBORKind, e.GoType)
}

// Unwrap returns the wrapped sentinel.
func (e *UnmarshalTypeError) Unwrap() error { return e.Err }

// typeMismatch reports a CBOR value of kind (named cborType in the
// message) that can't be stored in goType.
func typeMismatch(kind cbor.Kind, cborType string, goType reflect.Type) error {
	return &UnmarshalTypeError{
		CBORKind: kind, GoType: goType, Err: ErrTypeMismatch,
		msg: fmt.Sprintf("cbor: cannot decode %s into Go type %s", cborType, goType),
	}
}

// typeMismatchf reports a type mismatch with a custom message,
// prefixed "cbor: ".
func typeMismatchf(kind cbor.Kind, goType reflect.Type, format string, args ...any) error {
	return &UnmarshalTypeError{
		CBORKind: kind, GoType: goType, Err: ErrTypeMismatch,
		msg: "cbor: " + fmt.Sprintf(format, args...),
	}
}

// overflowErr reports a value out of range for goType. detail follows
// "<ErrOverflow>: ".
func overflowErr(kind cbor.Kind, goType reflect.Type, format string, args ...any) error {
	return &UnmarshalTypeError{
		CBORKind: kind, GoType: goType, Err: ErrOverflow,
		msg: ErrOverflow.Error() + ": " + fmt.Sprintf(format, args...),
	}
}

// unsupportedTarget reports a target that can't be set at all, or a
// kind no Go type accepts.
func unsupportedTarget(kind cbor.Kind, goType reflect.Type, format string, args ...any) error {
	return &UnmarshalTypeError{
		CBORKind: kind, GoType: goType, Err: ErrUnsupportedType,
		msg: "cbor: " + fmt.Sprintf(format, args...),
	}
}

// withField prefixes name onto the Field path of an UnmarshalTypeError
// in err's chain, so errors from nested structs report "Outer.Inner".
func withField(err error, name string) error {
	var ute *UnmarshalTypeError
	if errors.As(err, &ute) {
		if ute.Field == "" {
			ute.Field = name
		} else {
			ute.Field = name + "." + ute.Field
		}
	}
	return err
}
