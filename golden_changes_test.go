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

	// Proposal 022 — raw byte preservation.
	"root/unmarshal/rawmessage-unsorted-map": "proposal 022: RawMessage receives the original bytes",
}
