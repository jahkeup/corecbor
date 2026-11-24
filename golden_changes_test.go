// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor_test

// goldenChanges lists golden vector IDs whose results may differ from
// v0.2.2, keyed to the proposal that changes them. Per proposal 034 only
// safety and contract defect fixes may change existing behavior. Add an
// entry in the same change that alters the behavior.
var goldenChanges = map[string]string{
	// Proposal 021 — core codec safety fixes.
	"root/marshal/embedded-struct":            "proposal 021 D4: embedded struct fields are promoted, not nested",
	"root/marshal/embedded-unexported-struct": "proposal 021 D4: exported fields of unexported embedded structs are promoted (encoding/json rules)",
	"root/marshal/embedded-pointer-struct":    "proposal 021 D4: embedded pointers to structs are supported",
	"root/unmarshal/embedded-struct":          "proposal 021 D4: embedded struct fields decode by promoted name",
	"root/time/TimeTo-pre-1970":               "proposal 021 D5: pre-1970 TimeTo emits a negative integer",
	"root/time/AsTime-uint-max":               "proposal 021 D5: out-of-range epoch returns ErrTimeRange",
	"root/time/AsTime-float-huge":             "proposal 021 D5: out-of-range epoch returns ErrTimeRange",
	"root/time/AsTime-float-nan":              "proposal 021 D5: NaN epoch returns ErrTimeRange",
	"root/bigint/BigIntTo-nil":                "proposal 021 D5: BigIntTo(nil) returns Null instead of panicking",
	"root/unmarshal/any-bytes-key":            "proposal 021 D3: byte-string map keys decode as cbor.ByteKey instead of panicking",
	"root/unmarshal/any-array-key":            "proposal 021 D3: container map keys decode as cbor.EncodedKey instead of panicking",
	"root/unmarshal/any-negint-min":           "proposal 021 D7: NegInt beyond int64 decodes as *big.Int",
	"root/stream/nested-overflow":             "proposal 021 D6: nested containers count against the parent",
	"root/stream/deterministic-unsorted-map":  "proposal 021 D6: deterministic streams reject out-of-order map keys",

	// 021 D11: -2^64 renders as -18446744073709551616, not -0.
	"root/decode/forgiving/negint-min": "proposal 021 D11: NegInt formatted with unsigned arithmetic",
	"root/decode/strict/negint-min":    "proposal 021 D11: NegInt formatted with unsigned arithmetic",
	"root/diag/negint-min":             "proposal 021 D11: NegInt formatted with unsigned arithmetic",
	"root/diag-indicators/negint-min":  "proposal 021 D11: NegInt formatted with unsigned arithmetic",
	"root/diag-compact/negint-min":     "proposal 021 D11: NegInt formatted with unsigned arithmetic",

	// 021 D12: DiagIndicators renders RFC 8949 §8.1 indicators from the
	// source bytes. The byte view also shows every map entry as encoded,
	// so duplicate keys appear twice (the decoded Value keeps the last).
	"root/diag-indicators/nonshortest-0":         "proposal 021 D12: encoding indicator _0",
	"root/diag-indicators/nonshortest-1-u16":     "proposal 021 D12: encoding indicator _1",
	"root/diag-indicators/float32-1-nonshortest": "proposal 021 D12: float encoding indicator _2",
	"root/diag-indicators/bytes-indef":           "proposal 021 D12: indefinite-length byte string chunks",
	"root/diag-indicators/text-indef":            "proposal 021 D12: indefinite-length text string chunks",
	"root/diag-indicators/array-indef":           "proposal 021 D12: indefinite-length array indicator",
	"root/diag-indicators/map-indef":             "proposal 021 D12: indefinite-length map indicator",
	"root/diag-indicators/map-dup-key":           "proposal 021 D12/D19: Diagnostic renders every encoded map entry",
	"root/diag/map-dup-key":                      "proposal 021 D19: Diagnostic renders every encoded map entry, including duplicate keys",
	"root/diag-compact/map-dup-key":              "proposal 021 D19: Diagnostic renders every encoded map entry, including duplicate keys",
	"root/diag-indicators/map-dup-float-width":   "proposal 021 D12: float encoding indicator _2 on key",

	// 021 D13: invalid UTF-8 text renders as annotated bytes.
	"root/decode/forgiving/text-invalid-utf8": "proposal 021 D13: invalid UTF-8 text rendered as annotated bytes",
	"root/diag/text-invalid-utf8":             "proposal 021 D13: invalid UTF-8 text rendered as annotated bytes",
	"root/diag-indicators/text-invalid-utf8":  "proposal 021 D13: invalid UTF-8 text rendered as annotated bytes",
	"root/diag-compact/text-invalid-utf8":     "proposal 021 D13: invalid UTF-8 text rendered as annotated bytes",

	"root/encode/permissive/simple-24":         "proposal 021 D14: simple values 24-31 are not well-formed (RFC 8949 §3.3); ErrReservedSimple",
	"root/encode/core-deterministic/simple-24": "proposal 021 D14: simple values 24-31 are not well-formed (RFC 8949 §3.3); ErrReservedSimple",
	"root/encode/canonical/simple-24":          "proposal 021 D14: simple values 24-31 are not well-formed (RFC 8949 §3.3); ErrReservedSimple",
	"root/encode/ctap2/simple-24":              "proposal 021 D14: simple values 24-31 are not well-formed (RFC 8949 §3.3); ErrReservedSimple",

	"root/encode/core-deterministic/map-duplicate-key": "proposal 021 D15: deterministic modes reject duplicate map keys (RFC 8949 §5.6)",
	"root/encode/canonical/map-duplicate-key":          "proposal 021 D15: deterministic modes reject duplicate map keys (RFC 8949 §5.6)",
	"root/encode/ctap2/map-duplicate-key":              "proposal 021 D15: deterministic modes reject duplicate map keys (RFC 8949 §5.6)",

	"root/decode/forgiving/break-outside": "proposal 021 D16: a stray break is ErrUnexpectedBreak, not ErrTruncated",
	"root/decode/strict/break-outside":    "proposal 021 D16: a stray break is ErrUnexpectedBreak, not ErrTruncated",
	"root/diag/break-outside":             "proposal 021 D16: a stray break is ErrUnexpectedBreak, not ErrTruncated",
	"root/diag-indicators/break-outside":  "proposal 021 D16: a stray break is ErrUnexpectedBreak, not ErrTruncated",
	"root/diag-compact/break-outside":     "proposal 021 D16: a stray break is ErrUnexpectedBreak, not ErrTruncated",
	"root/sequence/decode-bad-tail":       "proposal 021 D16: a stray break in a sequence is ErrUnexpectedBreak, not ErrTruncated",
	"root/stream/iterator":                "proposal 021 D16: a stray break ends Stream with an error instead of as a clean end",

	// Proposal 022 — raw byte preservation.
	"root/unmarshal/rawmessage-unsorted-map": "proposal 022: RawMessage receives the original bytes",
	"root/raw/rawtag-unmarshal-unsorted":     "proposal 022: RawTag keeps the tag content's original bytes",
	"root/unmarshal/rawmessage-non-shortest": "proposal 022: RawMessage receives the original bytes (non-shortest int kept)",

	// Proposal 023 — strict decode tag policy.
	"root/decode/strict/tag1-epoch":               "proposal 023: StrictDecoder accepts tags (spec §3.2 excludes RejectUnknownTags)",
	"root/decode/strict/tag2-bignum":              "proposal 023: StrictDecoder accepts tags (spec §3.2 excludes RejectUnknownTags)",
	"root/decode/strict/tag2-leading-zero":        "proposal 023: StrictDecoder accepts tags (spec §3.2 excludes RejectUnknownTags)",
	"root/decode/strict/tag24":                    "proposal 023: StrictDecoder accepts tags (spec §3.2 excludes RejectUnknownTags)",
	"root/decode/strict/tag-unknown-100":          "proposal 023: StrictDecoder accepts tags (spec §3.2 excludes RejectUnknownTags)",
	"root/decode/strict/tag18-cose-empty":         "proposal 023: StrictDecoder accepts tags (spec §3.2 excludes RejectUnknownTags)",
	"root/decode/option/reject-unknown-tags-tag1": "proposal 023: RejectUnknownTags allows the spec §4.3 modeled tags (TagsModeled)",

	// Proposal 023: these errors now wrap ErrTypeMismatch (v0.2.2 had no sentinel); text unchanged.
	"root/unmarshal/struct-tag-mismatch":   "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/unmarshal/float-into-int":        "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/unmarshal/text-into-int":         "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/unmarshal/time-untagged":         "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/unmarshal/strict-decoder-struct": "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/time/AsTime-wrong-tag":           "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/time/AsTime-not-tag":             "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/bigint/AsBigInt-uint":            "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/nested/AsNestedCBOR-wrong":       "proposal 023: error now wraps ErrTypeMismatch (same message)",
	"root/raw/rawtag-unmarshal-not-tag":    "proposal 023: error now wraps ErrTypeMismatch (same message)",

	// Proposal 024 — serialization alignment and map key identity.
	"root/decode/forgiving/map-dup-nan-key":     "proposal 024: equal NaN keys are the same key (RFC 8949 §5.6.1 + erratum 8589); last write wins",
	"root/decode/forgiving/map-dup-float-width": "proposal 024: 1.0 at different float widths is the same key (RFC 8949 §5.6.1); last write wins",
	"root/decode/strict/map-dup-float-width":    "proposal 024: 1.0 at different float widths is a duplicate key (RFC 8949 §5.6.1)",
	"root/decode/option/reject-dupkeys-nan":     "proposal 024: equal NaN keys are duplicates (RFC 8949 §5.6.1 + erratum 8589)",

	"root/encode/core-deterministic/tag2-leading-zero": "proposal 024: deterministic modes write preferred bignums (RFC 8949 §3.4.3): leading zeros stripped, small values as integers",
	"root/encode/core-deterministic/tag3-small":        "proposal 024: deterministic modes write preferred bignums (RFC 8949 §3.4.3): small values as integers",
	"root/encode/canonical/tag2-leading-zero":          "proposal 024: deterministic modes write preferred bignums (RFC 8949 §3.4.3): leading zeros stripped, small values as integers",
	"root/encode/canonical/tag3-small":                 "proposal 024: deterministic modes write preferred bignums (RFC 8949 §3.4.3): small values as integers",
	"root/encode/ctap2/tag2-leading-zero":              "proposal 024: deterministic modes write preferred bignums (RFC 8949 §3.4.3): leading zeros stripped, small values as integers",
	"root/encode/ctap2/tag3-small":                     "proposal 024: deterministic modes write preferred bignums (RFC 8949 §3.4.3): small values as integers",
	"root/marshal/bigint-small":                        "proposal 024: Marshal (Core Deterministic) writes a small big.Int as an integer (RFC 8949 §3.4.3)",
	"root/marshal/bigint-negative":                     "proposal 024: Marshal (Core Deterministic) writes a small big.Int as an integer (RFC 8949 §3.4.3)",
	"root/bigint/BigIntTo-zero":                        "proposal 024: deterministic encoding of BigIntTo(0) is the integer 0 (RFC 8949 §3.4.3); the Value is unchanged",
	"root/bigint/BigIntTo-neg1":                        "proposal 024: deterministic encoding of BigIntTo(-1) is the integer -1 (RFC 8949 §3.4.3); the Value is unchanged",
	"root/unmarshal/bigint-from-uint":                  "proposal 024: Unmarshal into big.Int accepts major type 0/1 (keeps the Marshal round-trip now that small bignums encode as integers)",

	"root/encode-nonfinite/ctap2/float64-nan":         "proposal 024: CTAP2 writes every NaN as fb7ff8000000000000 (spec §2.2)",
	"root/encode-nonfinite/ctap2/float64-nan-payload": "proposal 024: CTAP2 writes every NaN as fb7ff8000000000000 (spec §2.2)",
	"root/encode-nonfinite/ctap2/float64-nan-neg":     "proposal 024: CTAP2 writes every NaN as fb7ff8000000000000 (spec §2.2)",
	"root/encode-nonfinite/ctap2/float32-nan-payload": "proposal 024: CTAP2 writes every NaN as fb7ff8000000000000 (spec §2.2)",

	// Proposal 037 — pre-release specification-departure review.
	"root/stream/scalars": "proposal 037 C13: StreamEncoder.WriteFloat32/64 follow the mode's float rules (shortest width in Core Deterministic, RFC 8949 §4.2.1)",
}
