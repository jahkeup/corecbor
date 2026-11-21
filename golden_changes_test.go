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
}
