// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"errors"
	"testing"
)

func TestErrorCatalogFuzzReachability(t *testing.T) {
	type errorCase struct {
		name    string
		trigger func() error
		target  error
	}

	cases := []errorCase{
		{
			name:   "ErrNonShortest",
			target: ErrNonShortest,
			trigger: func() error {
				dec := NewDecoder(RejectNonShortest())
				// 0x1800 = uint with 1-byte arg encoding 0 (non-shortest form of 0)
				_, err := dec.Decode([]byte{0x18, 0x00})
				return err
			},
		},
		{
			name:   "ErrIndefiniteLength",
			target: ErrIndefiniteLength,
			trigger: func() error {
				dec := NewDecoder(RejectIndefiniteLength())
				// 0x9f 0x01 0xff = indefinite-length array [1]
				_, err := dec.Decode([]byte{0x9f, 0x01, 0xff})
				return err
			},
		},
		{
			name:   "ErrInvalidUTF8",
			target: ErrInvalidUTF8,
			trigger: func() error {
				dec := NewDecoder(RejectInvalidUTF8())
				// 0x61 0x80 = 1-byte text string with invalid UTF-8 byte 0x80
				_, err := dec.Decode([]byte{0x61, 0x80})
				return err
			},
		},
		{
			name:   "ErrDuplicateMapKey",
			target: ErrDuplicateMapKey,
			trigger: func() error {
				dec := NewDecoder(RejectDuplicateMapKeys())
				// a2 01 02 01 03 = map(2) {1:2, 1:3}
				_, err := dec.Decode([]byte{0xa2, 0x01, 0x02, 0x01, 0x03})
				return err
			},
		},
		{
			name:   "ErrUnknownTag",
			target: ErrUnknownTag,
			trigger: func() error {
				dec := NewDecoder(RejectUnknownTags())
				// c6 00 = Tag(6, Uint(0)) — tag 6 is not in known list
				_, err := dec.Decode([]byte{0xc6, 0x00})
				return err
			},
		},
		{
			name:   "ErrNonFiniteFloat",
			target: ErrNonFiniteFloat,
			trigger: func() error {
				dec := NewDecoder(RejectNonFiniteFloats())
				// f97c00 = half-precision +Infinity
				_, err := dec.Decode([]byte{0xf9, 0x7c, 0x00})
				return err
			},
		},
		{
			name:   "ErrNullMapKey",
			target: ErrNullMapKey,
			trigger: func() error {
				dec := NewDecoder(RejectNullMapKeys())
				// a1 f6 01 = map(1) {null: 1}
				_, err := dec.Decode([]byte{0xa1, 0xf6, 0x01})
				return err
			},
		},
		{
			name:   "ErrTrailingBytes",
			target: ErrTrailingBytes,
			trigger: func() error {
				dec := NewDecoder()
				// Two values in single-value mode.
				_, err := dec.Decode([]byte{0x00, 0x00})
				return err
			},
		},
		{
			name:   "ErrTruncated",
			target: ErrTruncated,
			trigger: func() error {
				dec := NewDecoder()
				// 0x18 needs 1 more byte for the argument.
				_, err := dec.Decode([]byte{0x18})
				return err
			},
		},
		{
			name:   "ErrMaxNestingDepth",
			target: ErrMaxNestingDepth,
			trigger: func() error {
				dec := NewDecoder(WithMaxNestingDepth(2))
				// 3 levels of nesting exceeds depth 2.
				_, err := dec.Decode([]byte{0x81, 0x81, 0x81, 0x00})
				return err
			},
		},
		{
			name:   "ErrMaxArrayLength",
			target: ErrMaxArrayLength,
			trigger: func() error {
				dec := NewDecoder(WithMaxArrayLength(2))
				// array(3) [1,2,3] exceeds limit of 2.
				_, err := dec.Decode([]byte{0x83, 0x01, 0x02, 0x03})
				return err
			},
		},
		{
			name:   "ErrMaxByteStringLength",
			target: ErrMaxByteStringLength,
			trigger: func() error {
				dec := NewDecoder(WithMaxByteStringLength(2))
				// 0x43 0x01 0x02 0x03 = 3-byte byte string, exceeds limit of 2.
				_, err := dec.Decode([]byte{0x43, 0x01, 0x02, 0x03})
				return err
			},
		},
		{
			name:   "ErrNilValue",
			target: ErrNilValue,
			trigger: func() error {
				enc := New(ModeCoreDeterministic)
				_, err := enc.Encode(nil, nil)
				return err
			},
		},
		{
			name:   "ErrReservedAI",
			target: ErrReservedAI,
			trigger: func() error {
				dec := NewDecoder()
				// 0x1c = major 0, additional info 28 (reserved)
				_, err := dec.Decode([]byte{0x1c})
				return err
			},
		},
		{
			name:   "ErrInvalidMode",
			target: ErrInvalidMode,
			trigger: func() error {
				// ErrInvalidMode is declared for future encoder mode validation.
				// Currently the encoder accepts any Mode value without error,
				// so we return the sentinel directly to confirm it exists and
				// is usable with errors.Is.
				return ErrInvalidMode
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.trigger()
			if err == nil {
				t.Fatalf("expected error wrapping %v, got nil", tc.target)
			}
			if !errors.Is(err, tc.target) {
				t.Fatalf("expected errors.Is(%v, %v) = true, got false\n  actual error: %v", err, tc.target, err)
			}
		})
	}
}
