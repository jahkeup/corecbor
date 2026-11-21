// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"errors"
	"fmt"
	"slices"

	"github.com/jahkeup/corecbor/cbor"
)

// ErrPeerError wraps an EDHOC error message (RFC 9528 §6), whether
// received from the peer or produced for it. errors.As to *ErrorMessage
// for the details.
var ErrPeerError = errors.New("edhoc: error message")

// EDHOC error codes (RFC 9528 §6).
const (
	ErrCodeUnspecified        = 1 // ERR_INFO: text
	ErrCodeWrongSelectedSuite = 2 // ERR_INFO: SUITES_R
	ErrCodeUnknownCredential  = 3 // ERR_INFO: true
)

// ErrorMessage is an EDHOC error message (RFC 9528 §6). A Responder
// returns one (as the error) when it can't continue; send
// MarshalCBOR()'s bytes to the peer. An Initiator returns one when the
// peer sent an error message instead of message_2.
type ErrorMessage struct {
	Code    int64
	Info    string        // ERR_CODE 1
	SuitesR []CipherSuite // ERR_CODE 2

	// compat is an extra sentinel the error also matches, so callers
	// that checked v0.2's error for the same condition keep working.
	compat error
}

func (e *ErrorMessage) Error() string {
	switch e.Code {
	case ErrCodeWrongSelectedSuite:
		return fmt.Sprintf("edhoc: error message: wrong selected cipher suite (responder supports %v)", e.SuitesR)
	case ErrCodeUnknownCredential:
		return "edhoc: error message: unknown credential referenced"
	default:
		return fmt.Sprintf("edhoc: error message %d: %s", e.Code, e.Info)
	}
}

// Unwrap reports ErrPeerError, and ErrUnsupportedSuite for ERR_CODE 2.
func (e *ErrorMessage) Unwrap() []error {
	errs := []error{ErrPeerError}
	if e.Code == ErrCodeWrongSelectedSuite {
		errs = append(errs, ErrUnsupportedSuite)
	}
	if e.compat != nil {
		errs = append(errs, e.compat)
	}
	return errs
}

// MarshalCBOR encodes the error message as the CBOR sequence
// (ERR_CODE, ERR_INFO).
func (e *ErrorMessage) MarshalCBOR() ([]byte, error) {
	switch e.Code {
	case ErrCodeWrongSelectedSuite:
		if len(e.SuitesR) == 0 {
			return nil, fmt.Errorf("%w: SUITES_R is empty", ErrMessageFormat)
		}
		return encSeq(intItem(e.Code), encodeSuitesItem(e.SuitesR)), nil
	case ErrCodeUnknownCredential:
		return encSeq(intItem(e.Code), item(cbor.Bool(true))), nil
	default:
		return encSeq(intItem(e.Code), item(cbor.Text(e.Info))), nil
	}
}

// encodeSuitesItem encodes SUITES_I / SUITES_R: a single suite as an
// int, several as an array (RFC 9528 §5.2.2).
func encodeSuitesItem(s []CipherSuite) []byte {
	if len(s) == 1 {
		return intItem(int64(s[0]))
	}
	items := make([]cbor.Value, len(s))
	for i, c := range s {
		if c >= 0 {
			items[i] = cbor.Uint(uint64(c))
		} else {
			items[i] = cbor.NegInt(uint64(-1 - c))
		}
	}
	return item(cbor.MakeArrayFromSlice(items))
}

func decodeSuitesValue(v cbor.Value) ([]CipherSuite, error) {
	if v.Kind == cbor.KindArray {
		if len(v.Items) < 2 {
			return nil, fmt.Errorf("%w: suites array needs at least two entries", ErrMessageFormat)
		}
		out := make([]CipherSuite, len(v.Items))
		for i, it := range v.Items {
			n, err := valueInt(it, "cipher suite")
			if err != nil {
				return nil, err
			}
			out[i] = CipherSuite(n)
		}
		return out, nil
	}
	n, err := valueInt(v, "cipher suite")
	if err != nil {
		return nil, err
	}
	return []CipherSuite{CipherSuite(n)}, nil
}

// parseErrorMessage decodes an error message (ERR_CODE, ? ERR_INFO).
func parseErrorMessage(data []byte) (*ErrorMessage, error) {
	r := newSeqReader(data)
	code, err := r.nextInt("ERR_CODE")
	if err != nil {
		return nil, err
	}
	e := &ErrorMessage{Code: code}
	if !r.more() {
		return e, nil
	}
	info, _, err := r.next()
	if err != nil {
		return nil, err
	}
	switch {
	case code == ErrCodeWrongSelectedSuite:
		if e.SuitesR, err = decodeSuitesValue(info); err != nil {
			return nil, err
		}
	case info.Kind == cbor.KindText:
		e.Info = info.Str
	}
	if r.more() {
		return nil, fmt.Errorf("%w: trailing bytes after error message", ErrMessageFormat)
	}
	return e, nil
}

// RetrySuites returns SUITES_I for a new message_1 after the peer
// answered with ERR_CODE 2: prefs is the Initiator's full preference
// list; the result selects the most preferred suite the Responder
// supports, preceded by the more preferred ones (RFC 9528 §6.3.2).
func RetrySuites(prefs []CipherSuite, e *ErrorMessage) ([]CipherSuite, error) {
	if e == nil || e.Code != ErrCodeWrongSelectedSuite {
		return nil, fmt.Errorf("%w: not a wrong-selected-suite error", ErrUnsupportedSuite)
	}
	for i, s := range prefs {
		if slices.Contains(e.SuitesR, s) {
			return slices.Clone(prefs[:i+1]), nil
		}
	}
	return nil, fmt.Errorf("%w: no common cipher suite", ErrUnsupportedSuite)
}
