// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
)

// Tag numbers and helpers for envelope formats and published tag RFCs
// (proposal 026). See package cbor for the documentation of each.

const (
	TagCOSEEncrypt0      = cbor.TagCOSEEncrypt0
	TagCOSEMac0          = cbor.TagCOSEMac0
	TagCOSESign1         = cbor.TagCOSESign1
	TagCOSEEncrypt       = cbor.TagCOSEEncrypt
	TagCOSEMac           = cbor.TagCOSEMac
	TagCOSESign          = cbor.TagCOSESign
	TagCWT               = cbor.TagCWT
	TagUCCS              = cbor.TagUCCS
	TagDetachedEATBundle = cbor.TagDetachedEATBundle
	TagUUID              = cbor.TagUUID
	TagIPv4              = cbor.TagIPv4
	TagIPv6              = cbor.TagIPv6
	TagDays              = cbor.TagDays
	TagFullDate          = cbor.TagFullDate
	TagRelativeOID       = cbor.TagRelativeOID
	TagOID               = cbor.TagOID
	TagEnterpriseOID     = cbor.TagEnterpriseOID
	TagExtendedTime      = cbor.TagExtendedTime
	TagDuration          = cbor.TagDuration
	TagPeriod            = cbor.TagPeriod
	TagCBORSequenceFile  = cbor.TagCBORSequenceFile
	TagCBORLabeledData   = cbor.TagCBORLabeledData
)

var (
	ErrMalformedTag    = cbor.ErrMalformedTag
	ErrNonCanonicalTag = cbor.ErrNonCanonicalTag
)

// ExtendedTime is the decoded form of RFC 9581 tag 1001; see
// cbor.ExtendedTime.
type ExtendedTime = cbor.ExtendedTime

var (
	WrapEncodedCBOR  = cbor.WrapEncodedCBOR
	TagWrappedTo     = cbor.TagWrappedTo
	SequenceLabelTo  = cbor.SequenceLabelTo
	AsSequenceLabel  = cbor.AsSequenceLabel
	ContentFormatTag = cbor.ContentFormatTag
	AsContentFormat  = cbor.AsContentFormat
	UUIDTo           = cbor.UUIDTo
	AsUUID           = cbor.AsUUID
	DateTo           = cbor.DateTo
	DaysTo           = cbor.DaysTo
	AsDate           = cbor.AsDate
	ExtendedTimeTo   = cbor.ExtendedTimeTo
	AsExtendedTime   = cbor.AsExtendedTime
	DurationTo       = cbor.DurationTo
	AsDuration       = cbor.AsDuration
	IPTo             = cbor.IPTo
	PrefixTo         = cbor.PrefixTo
	InterfaceTo      = cbor.InterfaceTo
	AsIP             = cbor.AsIP
	AsPrefix         = cbor.AsPrefix
	OIDTo            = cbor.OIDTo
	RelativeOIDTo    = cbor.RelativeOIDTo
	AsOID            = cbor.AsOID
	AsRelativeOID    = cbor.AsRelativeOID
)

// EncodeEncodedCBOR encodes v with e and wraps the result in tag 24
// (RFC 8949 §3.4.5.1). The wrapped bytes are what a signature over
// "<<v>>" (CDDL) covers.
func (e *Encoder) EncodeEncodedCBOR(v Value) (Value, error) {
	b, err := e.Encode(nil, v)
	if err != nil {
		return Value{}, err
	}
	return cbor.WrapEncodedCBOR(b), nil
}

// DecodeEncodedCBOR unwraps a tag-24 Value and decodes its content with
// d, which must be exactly one data item (ErrTrailingBytes otherwise).
// It returns the decoded Value and the embedded bytes exactly as they
// appear in t, so callers can hash or verify them. As with Decode, the
// Value is valid until the next decode on d unless d was built with
// WithoutInternalArena.
func (d *Decoder) DecodeEncodedCBOR(t Value) (Value, []byte, error) {
	raw, err := cbor.AsNestedCBOR(t)
	if err != nil {
		return Value{}, nil, fmt.Errorf("%w: %w", cbor.ErrMalformedTag, err)
	}
	v, err := d.Decode(raw)
	if err != nil {
		return Value{}, nil, err
	}
	return v, raw, nil
}
