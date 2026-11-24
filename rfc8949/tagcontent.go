// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"encoding/base64"
	"net/url"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

// tagContentProblem reports why content is not valid content for tag
// id, or "" when it is valid or the tag is not one this check covers.
// It covers the tags whose content RFC 8949 §3.4
// defines, and the tags the library models (encoder-decoder-spec.md
// §4.3) or has helpers for:
//
//   - 0: a text string in RFC 3339 date/time format (§3.4.1), as
//     time.Parse with time.RFC3339 reads it;
//   - 1: an integer or a float (§3.4.2);
//   - 2, 3: a byte string (§3.4.3);
//   - 4, 5: an array of an integer exponent and an integer or bignum
//     mantissa (§3.4.4);
//   - 24: a byte string holding exactly one well-formed data item
//     (§3.4.5.1); the item itself is not validated;
//   - 32: a URI-reference text string (§3.4.5.3), as url.Parse reads it;
//   - 33, 34: base64url without padding and base64 with padding, with
//     zero padding bits (§3.4.5.3);
//   - 35: a text string; 258: an array;
//   - 64–87 (RFC 8746 typed arrays, 76 reserved): a byte string whose
//     length is a multiple of the element size;
//   - 40, 1040 (RFC 8746 multi-dimensional arrays): [dimensions, data]
//     with data an array or typed array of the dimensions' product;
//     41 (homogeneous array): an array of elements of one type.
//
// Other tags, 21–23 and 55799 included, accept any content.
func tagContentProblem(id uint64, c cbor.Value) string {
	switch id {
	case cbor.TagDateTimeString:
		if c.Kind != cbor.KindText {
			return "tag 0 content must be a text string"
		}
		if _, err := time.Parse(time.RFC3339, c.Str); err != nil {
			return "tag 0 content is not an RFC 3339 date/time"
		}
	case cbor.TagEpochDateTime:
		switch c.Kind {
		case cbor.KindUint, cbor.KindNegInt, cbor.KindFloat32, cbor.KindFloat64:
		default:
			return "tag 1 content must be an integer or a float"
		}
	case cbor.TagUnsignedBignum, cbor.TagNegativeBignum:
		if c.Kind != cbor.KindBytes {
			return "bignum content must be a byte string"
		}
	case 4, 5:
		if c.Kind != cbor.KindArray || len(c.Items) != 2 || !isInt(c.Items[0]) || !isInt(c.Items[1]) && !isBignum(c.Items[1]) {
			return "decimal fraction or bigfloat content must be [integer exponent, integer or bignum mantissa]"
		}
	case cbor.TagEncodedCBOR:
		if c.Kind != cbor.KindBytes {
			return "tag 24 content must be a byte string"
		}
		n, err := NewCursor(c.Bstr, DecodeOpts{}).Skip()
		if err != nil || n != len(c.Bstr) {
			return "tag 24 content is not exactly one well-formed data item"
		}
	case 32:
		if c.Kind != cbor.KindText {
			return "tag 32 content must be a text string"
		}
		if _, err := url.Parse(c.Str); err != nil {
			return "tag 32 content is not a URI-reference"
		}
	case 33, 34:
		if c.Kind != cbor.KindText {
			return "base64 tag content must be a text string"
		}
		enc := base64.RawURLEncoding.Strict()
		if id == 34 {
			enc = base64.StdEncoding.Strict()
		}
		if _, err := enc.DecodeString(c.Str); err != nil {
			return "tag content is not valid base64url (33, unpadded) or base64 (34, padded)"
		}
	case 35:
		if c.Kind != cbor.KindText {
			return "tag 35 content must be a text string"
		}
	case 258:
		if c.Kind != cbor.KindArray {
			return "tag 258 content must be an array"
		}
	case cbor.TagMultiDimArray, cbor.TagMultiDimArrayColumnMajor:
		if _, err := cbor.AsMultiDimArray(cbor.MakeTag(id, c)); err != nil {
			return "multi-dimensional array content must be [dimensions, data] with matching element count"
		}
	case cbor.TagHomogeneousArray:
		if _, err := cbor.AsHomogeneousArray(cbor.MakeTag(id, c)); err != nil {
			return "tag 41 content must be an array of elements of one type"
		}
	default:
		if size := typedArrayElemSize(id); size > 0 {
			if c.Kind != cbor.KindBytes {
				return "typed array content must be a byte string"
			}
			if len(c.Bstr)%size != 0 {
				return "typed array length is not a multiple of its element size"
			}
		}
	}
	return ""
}

// typedArrayElemSize returns the element size in bytes of RFC 8746
// typed array tag id (64–87), or 0 for any other tag, including the
// reserved 76.
func typedArrayElemSize(id uint64) int {
	if id < 64 || id > 87 || id == 76 {
		return 0
	}
	f, ll := id&0x10 != 0, int(id&0x3)
	if f {
		return 2 << ll // float16, 32, 64, 128
	}
	return 1 << ll
}

func isInt(v cbor.Value) bool { return v.Kind == cbor.KindUint || v.Kind == cbor.KindNegInt }

func isBignum(v cbor.Value) bool {
	return v.Kind == cbor.KindTag && (v.Num == cbor.TagUnsignedBignum || v.Num == cbor.TagNegativeBignum) &&
		len(v.Items) == 1 && v.Items[0].Kind == cbor.KindBytes
}
