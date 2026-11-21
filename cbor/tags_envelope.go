// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "fmt"

// Tag numbers for envelope formats and published tag RFCs (proposal
// 026). These hand-picked names are the ones to use in code; the
// generated names in package registry exist for lookup and diagnostics.
const (
	TagCOSEEncrypt0      uint64 = 16    // RFC 9052 §2
	TagCOSEMac0          uint64 = 17    // RFC 9052 §2
	TagCOSESign1         uint64 = 18    // RFC 9052 §2
	TagCOSEEncrypt       uint64 = 96    // RFC 9052 §2
	TagCOSEMac           uint64 = 97    // RFC 9052 §2
	TagCOSESign          uint64 = 98    // RFC 9052 §2
	TagCWT               uint64 = 61    // RFC 8392 §6
	TagUCCS              uint64 = 601   // RFC 9781
	TagDetachedEATBundle uint64 = 602   // RFC 9711 §5
	TagUUID              uint64 = 37    // RFC 9562 §4 (binary UUID)
	TagIPv4              uint64 = 52    // RFC 9164
	TagIPv6              uint64 = 54    // RFC 9164
	TagDays              uint64 = 100   // RFC 8943: days since 1970-01-01
	TagFullDate          uint64 = 1004  // RFC 8943: RFC 3339 full-date
	TagRelativeOID       uint64 = 110   // RFC 9090
	TagOID               uint64 = 111   // RFC 9090
	TagEnterpriseOID     uint64 = 112   // RFC 9090: relative to 1.3.6.1.4.1
	TagExtendedTime      uint64 = 1001  // RFC 9581 §3
	TagDuration          uint64 = 1002  // RFC 9581 §4
	TagPeriod            uint64 = 1003  // RFC 9581 §5
	TagCBORSequenceFile  uint64 = 55800 // RFC 9277 §2.3: labeled CBOR sequence
	TagCBORLabeledData   uint64 = 55801 // RFC 9277 App. D: labeled non-CBOR data
)

// WrapEncodedCBOR returns Tag(24, Bytes(encoded)) (RFC 8949 §3.4.5.1).
// encoded MUST already be a single well-formed CBOR data item; use
// Encoder.EncodeEncodedCBOR in the root package to build it from a
// Value. AsNestedCBOR (or Decoder.DecodeEncodedCBOR) is the inverse.
func WrapEncodedCBOR(encoded []byte) Value {
	return MakeTag(TagEncodedCBOR, Bytes(encoded))
}

// --- RFC 9277: magic numbers for stored CBOR ---

// borLabel is the constant content of an RFC 9277 label: the byte string
// 'BOR', which encodes as the ASCII bytes "CBOR".
var borLabel = []byte("BOR")

// TagWrappedTo returns the RFC 9277 §2.2 "CBOR Tag Wrapped" envelope
// 55799(protocolTag(v)). protocolTag identifies the CBOR protocol; RFC
// 9277 recommends a 4-byte tag number with no zero bytes.
func TagWrappedTo(protocolTag uint64, v Value) Value {
	return MakeTag(TagSelfDescribe, MakeTag(protocolTag, v))
}

// SequenceLabelTo returns the RFC 9277 §2.3 label for a CBOR sequence
// file, 55800(protocolTag('BOR')), to write as the first item of the
// sequence.
func SequenceLabelTo(protocolTag uint64) Value {
	return MakeTag(TagCBORSequenceFile, MakeTag(protocolTag, Bytes(borLabel)))
}

// AsSequenceLabel returns the protocol tag of an RFC 9277 label: tag
// 55800 (labeled CBOR sequence) or 55801 (labeled non-CBOR data)
// enclosing protocolTag('BOR').
func AsSequenceLabel(v Value) (protocolTag uint64, err error) {
	if v.Kind != KindTag || (v.TagID() != TagCBORSequenceFile && v.TagID() != TagCBORLabeledData) {
		return 0, fmt.Errorf("%w: expected tag 55800 or 55801", ErrMalformedTag)
	}
	inner := v.TagInner()
	if inner.Kind != KindTag {
		return 0, fmt.Errorf("%w: RFC 9277 label must enclose a protocol tag", ErrMalformedTag)
	}
	content := inner.TagInner()
	if content.Kind != KindBytes || string(content.BytesVal()) != string(borLabel) {
		return 0, fmt.Errorf("%w: RFC 9277 label content must be 'BOR'", ErrMalformedTag)
	}
	return inner.TagID(), nil
}

// ContentFormatTag returns the RFC 9277 App. B tag number
// TN(ct) = 0x63740101 + (ct / 255) * 256 + ct % 255 for CoAP
// Content-Format ct. Content-Formats 65025 and above have no tag.
func ContentFormatTag(ct uint16) (uint64, error) {
	if ct >= 65025 {
		return 0, fmt.Errorf("%w: no tag for Content-Format %d (>= 65025)", ErrMalformedTag, ct)
	}
	c := uint64(ct)
	return 0x63740101 + (c/255)*256 + c%255, nil
}

// AsContentFormat is the inverse of ContentFormatTag. ok is false when
// tag isn't TN(ct) for any Content-Format.
func AsContentFormat(tag uint64) (ct uint16, ok bool) {
	if tag < 0x63740101 || tag > 0x6374ffff {
		return 0, false
	}
	off := tag - 0x63740101
	hi, lo := off/256, off%256
	if lo >= 255 {
		return 0, false
	}
	v := hi*255 + lo
	if v >= 65025 {
		return 0, false
	}
	return uint16(v), true
}
