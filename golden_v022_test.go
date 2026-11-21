// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor_test

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	cc "github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// TestGoldenV022 enforces proposal 034: exported identifiers called
// without new options reproduce v0.2.2 results. Intended changes are
// listed in golden_changes_test.go.
func TestGoldenV022(t *testing.T) {
	g.Check(t, "testdata/golden/v0.2.2/root.json", rootGoldenCases(), goldenChanges)
}

var rootSentinels = []g.Sentinel{
	{Name: "ErrNonShortest", Err: cc.ErrNonShortest},
	{Name: "ErrIndefiniteLength", Err: cc.ErrIndefiniteLength},
	{Name: "ErrInvalidUTF8", Err: cc.ErrInvalidUTF8},
	{Name: "ErrDuplicateMapKey", Err: cc.ErrDuplicateMapKey},
	{Name: "ErrUnknownTag", Err: cc.ErrUnknownTag},
	{Name: "ErrNonFiniteFloat", Err: cc.ErrNonFiniteFloat},
	{Name: "ErrNullMapKey", Err: cc.ErrNullMapKey},
	{Name: "ErrTrailingBytes", Err: cc.ErrTrailingBytes},
	{Name: "ErrTruncated", Err: cc.ErrTruncated},
	{Name: "ErrMaxNestingDepth", Err: cc.ErrMaxNestingDepth},
	{Name: "ErrMaxArrayLength", Err: cc.ErrMaxArrayLength},
	{Name: "ErrMaxByteStringLength", Err: cc.ErrMaxByteStringLength},
	{Name: "ErrInvalidMode", Err: cc.ErrInvalidMode},
	{Name: "ErrNilValue", Err: cc.ErrNilValue},
	{Name: "ErrReservedAI", Err: cc.ErrReservedAI},
	{Name: "ErrNonStringKey", Err: cc.ErrNonStringKey},
	{Name: "ErrMemoryBudgetExceeded", Err: cbor.ErrMemoryBudgetExceeded},
	{Name: "ErrOverflow", Err: cc.ErrOverflow},
	{Name: "ErrNotPointer", Err: cc.ErrNotPointer},
	{Name: "ErrUnsupportedType", Err: cc.ErrUnsupportedType},
	{Name: "ErrIndefiniteNotPermitted", Err: cc.ErrIndefiniteNotPermitted},
}

func hexOf(b []byte, err error) string { return g.Hex(b, err, rootSentinels) }
func strOf(s string, err error) string { return g.Str(s, err, rootSentinels) }

type namedValue struct {
	name string
	v    cc.Value
}

func entry(k, v cc.Value) cc.MapEntry { return cc.MapEntry{Key: k, Value: v} }

func encodeCorpus() []namedValue {
	return []namedValue{
		{"uint-0", cc.Uint(0)},
		{"uint-23", cc.Uint(23)},
		{"uint-24", cc.Uint(24)},
		{"uint-255", cc.Uint(255)},
		{"uint-256", cc.Uint(256)},
		{"uint-65535", cc.Uint(65535)},
		{"uint-65536", cc.Uint(65536)},
		{"uint-2p32m1", cc.Uint(math.MaxUint32)},
		{"uint-2p32", cc.Uint(math.MaxUint32 + 1)},
		{"uint-max", cc.Uint(math.MaxUint64)},
		{"negint-m1", cc.NegInt(0)},
		{"negint-m24", cc.NegInt(23)},
		{"negint-m25", cc.NegInt(24)},
		{"negint-min", cc.NegInt(math.MaxUint64)},
		{"float64-0", cc.Float64(0)},
		{"float64-neg0", cc.Float64(math.Copysign(0, -1))},
		{"float64-1", cc.Float64(1)},
		{"float64-1.5", cc.Float64(1.5)},
		{"float64-65504", cc.Float64(65504)},
		{"float64-100000", cc.Float64(100000)},
		{"float64-1.1", cc.Float64(1.1)},
		{"float64-1e300", cc.Float64(1e300)},
		{"float64-subnormal-min", cc.Float64(math.SmallestNonzeroFloat64)},
		{"float64-half-subnormal", cc.Float64(5.960464477539063e-08)},
		{"float64-nan", cc.Float64(math.NaN())},
		{"float64-nan-payload", cc.Value{Kind: cc.KindFloat64, Num: 0x7ff8000000000001}},
		{"float64-nan-neg", cc.Value{Kind: cc.KindFloat64, Num: 0xfff8000000000000}},
		{"float64-inf", cc.Float64(math.Inf(1))},
		{"float64-neginf", cc.Float64(math.Inf(-1))},
		{"float32-1", cc.Float32(1)},
		{"float32-max", cc.Float32(math.MaxFloat32)},
		{"float32-nan-payload", cc.Value{Kind: cc.KindFloat32, Num: 0x7fc00001}},
		{"text-empty", cc.Text("")},
		{"text-ietf", cc.Text("IETF")},
		{"text-unicode", cc.Text("üñí水")},
		{"text-24", cc.Text(strings.Repeat("x", 24))},
		{"text-invalid-utf8", cc.Text("\xff")},
		{"bytes-empty", cc.Bytes([]byte{})},
		{"bytes-4", cc.Bytes([]byte{1, 2, 3, 4})},
		{"array-empty", cc.MakeArray()},
		{"array-nested", cc.MakeArray(cc.Uint(1), cc.MakeArray(cc.Uint(2), cc.Uint(3)))},
		{"array-25", func() cc.Value {
			items := make([]cc.Value, 25)
			for i := range items {
				items[i] = cc.Uint(uint64(i))
			}
			return cc.MakeArrayFromSlice(items)
		}()},
		{"map-empty", cc.MakeMap()},
		{"map-unsorted-text", cc.MakeMap(entry(cc.Text("b"), cc.Uint(1)), entry(cc.Text("a"), cc.Uint(2)))},
		{"map-lenfirst-vs-bytewise", cc.MakeMap(entry(cc.Text("aa"), cc.Uint(1)), entry(cc.Text("b"), cc.Uint(2)))},
		{"map-mixed-keys", cc.MakeMap(
			entry(cc.Text("z"), cc.Uint(4)),
			entry(cc.Uint(100), cc.Uint(2)),
			entry(cc.Bytes([]byte{0}), cc.Uint(5)),
			entry(cc.NegInt(0), cc.Uint(3)),
			entry(cc.Uint(10), cc.Uint(1)),
		)},
		{"map-nested-unsorted", cc.MakeMap(entry(cc.Text("y"), cc.MakeMap(entry(cc.Uint(2), cc.Null()), entry(cc.Uint(1), cc.Bool(true)))), entry(cc.Text("x"), cc.Uint(0)))},
		{"map-duplicate-key", cc.MakeMap(entry(cc.Text("a"), cc.Uint(1)), entry(cc.Text("a"), cc.Uint(2)))},
		{"map-null-key", cc.MakeMap(entry(cc.Null(), cc.Uint(1)))},
		{"tag0-datetime", cc.MakeTag(cc.TagDateTimeString, cc.Text("2013-03-21T20:04:00Z"))},
		{"tag1-epoch", cc.MakeTag(cc.TagEpochDateTime, cc.Uint(1363896240))},
		{"tag1-float", cc.MakeTag(cc.TagEpochDateTime, cc.Float64(1363896240.5))},
		{"tag2-bignum", cc.MakeTag(cc.TagUnsignedBignum, cc.Bytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0}))},
		{"tag2-leading-zero", cc.MakeTag(cc.TagUnsignedBignum, cc.Bytes([]byte{0, 1}))},
		{"tag3-small", cc.MakeTag(cc.TagNegativeBignum, cc.Bytes([]byte{0}))},
		{"tag24-encoded", cc.MakeTag(cc.TagEncodedCBOR, cc.Bytes([]byte{0x64, 'I', 'E', 'T', 'F'}))},
		{"tag32-uri", cc.MakeTag(cc.TagURI, cc.Text("http://www.example.com"))},
		{"tag55799", cc.MakeTag(cc.TagSelfDescribe, cc.Uint(1))},
		{"tag-nil-inner", cc.Value{Kind: cc.KindTag, Num: 5}},
		{"bool-false", cc.Bool(false)},
		{"bool-true", cc.Bool(true)},
		{"null", cc.Null()},
		{"undefined", cc.Undefined()},
		{"simple-16", cc.Simple(16)},
		{"simple-24", cc.Simple(24)},
		{"simple-255", cc.Simple(255)},
		{"invalid-zero-value", cc.Value{}},
	}
}

var modes = []struct {
	name string
	mode cc.Mode
}{
	{"permissive", cc.ModePermissive},
	{"core-deterministic", cc.ModeCoreDeterministic},
	{"canonical", cc.ModeCanonical},
	{"ctap2", cc.ModeCTAP2},
}

// decodeCorpus lists hex inputs for Decode/Diagnostic vectors.
var decodeCorpus = []struct{ name, hex string }{
	{"uint-0", "00"},
	{"uint-1000000", "1a000f4240"},
	{"uint-max", "1bffffffffffffffff"},
	{"negint-min", "3bffffffffffffffff"},
	{"nonshortest-0", "1800"},
	{"nonshortest-1-u16", "190001"},
	{"bytes-indef", "5f42010243030405ff"},
	{"text-indef", "7f657374726561646d696e67ff"},
	{"array-indef", "9f0102ff"},
	{"map-indef", "bf616101ff"},
	{"map-dup-key", "a2616101616102"},
	{"map-unsorted", "a2616201616102"},
	{"map-null-key", "a1f601"},
	{"map-dup-nan-key", "a2f97e0001f97e0002"},
	{"map-dup-float-width", "a2f93c0001fa3f80000002"},
	{"text-invalid-utf8", "61ff"},
	{"float16-1", "f93c00"},
	{"float16-nan", "f97e00"},
	{"float16-inf", "f97c00"},
	{"float32-1-nonshortest", "fa3f800000"},
	{"float64-1.1", "fb3ff199999999999a"},
	{"tag1-epoch", "c11a514b67b0"},
	{"tag2-bignum", "c249010000000000000000"},
	{"tag2-leading-zero", "c2420001"},
	{"tag24", "d818456449455446"},
	{"tag55799", "d9d9f701"},
	{"tag-unknown-100", "d86401"},
	{"tag18-cose-empty", "d28440a0f640"},
	{"reserved-ai-28", "1c"},
	{"trailing-bytes", "0000"},
	{"truncated-u32", "1a0001"},
	{"break-outside", "ff"},
	{"simple-2byte-lt32", "f818"},
	{"simple-32", "f820"},
	{"undefined", "f7"},
	{"bytes-len-huge", "5bffffffffffffffff00"},
	{"array-len-huge", "9bffffffffffffffff"},
	{"empty", ""},
}

func deepArray(depth int) []byte {
	b := bytes.Repeat([]byte{0x81}, depth)
	return append(b, 0x00)
}

func rootGoldenCases() []g.Case {
	var cases []g.Case
	add := func(id string, run func() string) { cases = append(cases, g.Case{ID: id, Run: run}) }

	// Encode: every corpus value in every mode, default options.
	for _, m := range modes {
		enc := cc.New(m.mode)
		for _, nv := range encodeCorpus() {
			add("root/encode/"+m.name+"/"+nv.name, func() string { return hexOf(enc.Encode(nil, nv.v)) })
		}
		// Non-finite floats with the existing opt-in.
		nf := cc.New(m.mode, cc.AllowNonFiniteFloats())
		for _, nv := range encodeCorpus() {
			if !strings.HasPrefix(nv.name, "float") {
				continue
			}
			add("root/encode-nonfinite/"+m.name+"/"+nv.name, func() string { return hexOf(nf.Encode(nil, nv.v)) })
		}
	}
	add("root/encode/invalid-mode", func() string { return hexOf(cc.New(cc.Mode(99)).Encode(nil, cc.Uint(1))) })
	add("root/encode/allow-invalid-utf8", func() string {
		return hexOf(cc.New(cc.ModeCoreDeterministic, cc.AllowInvalidUTF8()).Encode(nil, cc.Text("\xff")))
	})
	add("root/encode/shared-core-deterministic", func() string {
		return hexOf(cc.NewShared(cc.ModeCoreDeterministic).Encode(nil, cc.MakeMap(entry(cc.Text("b"), cc.Uint(1)), entry(cc.Text("a"), cc.Uint(2)))))
	})

	// Decode: forgiving and strict, recorded as diagnostic notation.
	for _, in := range decodeCorpus {
		add("root/decode/forgiving/"+in.name, func() string {
			v, err := cc.NewDecoder().Decode(g.MustHex(in.hex))
			return strOf(cc.DiagnosticValue(v), err)
		})
		add("root/decode/strict/"+in.name, func() string {
			v, err := cc.StrictDecoder().Decode(g.MustHex(in.hex))
			return strOf(cc.DiagnosticValue(v), err)
		})
		add("root/diag/"+in.name, func() string { return strOf(cc.Diagnostic(g.MustHex(in.hex))) })
		add("root/diag-indicators/"+in.name, func() string {
			return strOf(cc.Diagnostic(g.MustHex(in.hex), cc.DiagIndicators()))
		})
		add("root/diag-compact/"+in.name, func() string {
			return strOf(cc.Diagnostic(g.MustHex(in.hex), cc.DiagCompact()))
		})
	}
	add("root/decode/forgiving/depth-256", func() string {
		v, err := cc.NewDecoder().Decode(deepArray(256))
		return strOf(fmt.Sprintf("%d", v.Kind), err) // %d: Kind has a String method since 025
	})
	add("root/decode/forgiving/depth-257", func() string {
		v, err := cc.NewDecoder().Decode(deepArray(257))
		return strOf(fmt.Sprintf("%d", v.Kind), err) // %d: Kind has a String method since 025
	})
	add("root/decode/max-array-2", func() string {
		_, err := cc.NewDecoder(cc.WithMaxArrayLength(2)).Decode(g.MustHex("83010203"))
		return g.OK(err, rootSentinels)
	})
	add("root/decode/max-bytes-2", func() string {
		_, err := cc.NewDecoder(cc.WithMaxByteStringLength(2)).Decode(g.MustHex("43010203"))
		return g.OK(err, rootSentinels)
	})
	add("root/decode/memory-budget-16", func() string {
		_, err := cc.NewDecoder(cc.WithMemoryBudget(16)).Decode(g.MustHex("5820" + strings.Repeat("00", 32)))
		return g.OK(err, rootSentinels)
	})
	for _, opt := range []struct {
		name string
		o    cc.DecoderOption
		hex  string
	}{
		{"reject-indefinite", cc.RejectIndefiniteLength(), "9f01ff"},
		{"reject-nonshortest", cc.RejectNonShortest(), "1800"},
		{"reject-nonshortest-float", cc.RejectNonShortest(), "fa3f800000"},
		{"reject-utf8", cc.RejectInvalidUTF8(), "61ff"},
		{"reject-dupkeys", cc.RejectDuplicateMapKeys(), "a2616101616102"},
		{"reject-dupkeys-nan", cc.RejectDuplicateMapKeys(), "a2f97e0001f97e0002"},
		{"reject-unknown-tags-tag1", cc.RejectUnknownTags(), "c11a514b67b0"},
		{"reject-nonfinite", cc.RejectNonFiniteFloats(), "f97c00"},
		{"reject-nullkeys", cc.RejectNullMapKeys(), "a1f601"},
	} {
		add("root/decode/option/"+opt.name, func() string {
			v, err := cc.NewDecoder(opt.o).Decode(g.MustHex(opt.hex))
			return strOf(cc.DiagnosticValue(v), err)
		})
	}

	addMarshalCases(add)
	addUnmarshalCases(add)
	addHelperCases(add)
	addRawCases(add)
	addSequenceCases(add)
	addStreamCases(add)
	addStorageCorpusCases(add)
	return cases
}

// variant wraps v as a single-entry map keyed by a variant tag, the
// shape a deterministic storage consumer uses for typed attribute values.
func variant(tag string, v cc.Value) cc.Value {
	return cc.MakeMap(entry(cc.Text(tag), v))
}

// storageCorpus is a variant-tag storage corpus: text, numbers carried
// as text, bytes, bool, null, nested maps and lists, and sets as
// pre-sorted arrays, including text that isn't valid UTF-8. Its Core
// Deterministic encoding (with AllowInvalidUTF8) is used as AEAD AAD and
// checksum input by such consumers, so it must stay byte-identical.
func storageCorpus() []namedValue {
	item := func(pairs ...cc.MapEntry) cc.Value { return cc.MakeMap(pairs...) }
	return []namedValue{
		{"s", variant("s", cc.Text("hello"))},
		{"s-empty", variant("s", cc.Text(""))},
		{"s-invalid-utf8", variant("s", cc.Text("\xff\xfe ok"))},
		{"s-long", variant("s", cc.Text(strings.Repeat("x", 300)))},
		{"n-int", variant("n", cc.Text("12345"))},
		{"n-decimal", variant("n", cc.Text("-0.000123456789012345678901234567890123456"))},
		{"b", variant("b", cc.Bytes([]byte{0, 1, 2, 0xff}))},
		{"b-empty", variant("b", cc.Bytes([]byte{}))},
		{"bool-true", variant("bool", cc.Bool(true))},
		{"bool-false", variant("bool", cc.Bool(false))},
		{"null", variant("null", cc.Bool(true))},
		{"ss", variant("ss", cc.MakeArray(cc.Text("a"), cc.Text("b"), cc.Text("c")))},
		{"ns", variant("ns", cc.MakeArray(cc.Text("1"), cc.Text("10"), cc.Text("2")))},
		{"bs", variant("bs", cc.MakeArray(cc.Bytes([]byte{1}), cc.Bytes([]byte{2, 3})))},
		{"l", variant("l", cc.MakeArray(variant("s", cc.Text("x")), variant("n", cc.Text("1")), variant("null", cc.Bool(true))))},
		{"m", variant("m", item(
			entry(cc.Text("zeta"), variant("s", cc.Text("z"))),
			entry(cc.Text("alpha"), variant("n", cc.Text("1"))),
			entry(cc.Text("mid"), variant("bool", cc.Bool(false))),
		))},
		{"item", item(
			entry(cc.Text("pk"), variant("s", cc.Text("user#42"))),
			entry(cc.Text("sk"), variant("s", cc.Text("profile"))),
			entry(cc.Text("age"), variant("n", cc.Text("42"))),
			entry(cc.Text("tags"), variant("ss", cc.MakeArray(cc.Text("admin"), cc.Text("ops")))),
			entry(cc.Text("blob"), variant("b", cc.Bytes([]byte("\x00\x01binary")))),
			entry(cc.Text("nested"), variant("m", item(
				entry(cc.Text("list"), variant("l", cc.MakeArray(variant("n", cc.Text("3")), variant("s", cc.Text("\xc3\x28"))))),
				entry(cc.Text("k"), variant("null", cc.Bool(true))),
			))),
		)},
		{"item-wide", func() cc.Value {
			var pairs []cc.MapEntry
			for i := range 40 {
				pairs = append(pairs, entry(cc.Text(fmt.Sprintf("attr%02d", 39-i)), variant("n", cc.Text(fmt.Sprint(i)))))
			}
			return cc.MakeMap(pairs...)
		}()},
	}
}

func addStorageCorpusCases(add func(string, func() string)) {
	enc := cc.NewShared(cc.ModeCoreDeterministic, cc.AllowInvalidUTF8())
	for _, nv := range storageCorpus() {
		add("root/storage-corpus/encode/"+nv.name, func() string { return hexOf(enc.Encode(nil, nv.v)) })
		add("root/storage-corpus/reencode/"+nv.name, func() string {
			b, err := enc.Encode(nil, nv.v)
			if err != nil {
				return hexOf(nil, err)
			}
			v, err := cc.NewDecoder().Decode(b)
			if err != nil {
				return hexOf(nil, err)
			}
			return hexOf(enc.Encode(nil, v))
		})
	}
}

type GoldenInner struct {
	A int    `cbor:"a"`
	B string `cbor:"b"`
}

type GoldenEmbedded struct {
	GoldenInner
	C int `cbor:"c"`
}

type goldenInnerUnexported struct {
	A int `cbor:"a"`
}

type GoldenEmbeddedUnexported struct {
	goldenInnerUnexported
	C int `cbor:"c"`
}

type GoldenEmbeddedPtr struct {
	*GoldenInner
	C int `cbor:"c"`
}

type goldenTagged struct {
	Name     string            `cbor:"name"`
	Count    int               `cbor:"count,omitempty"`
	Skip     string            `cbor:"-"`
	IntKey   int               `cbor:"1"`
	NegKey   string            `cbor:"-2"`
	When     time.Time         `cbor:"when,omitempty"`
	Wrapped  string            `cbor:"w,tag=32"`
	Raw      []byte            `cbor:"raw"`
	Arr      [4]byte           `cbor:"arr"`
	F32      float32           `cbor:"f32"`
	Strs     []string          `cbor:"strs"`
	M        map[string]int    `cbor:"m"`
	NilMap   map[string]string `cbor:"nilmap"`
	NilSlice []int             `cbor:"nilslice"`
	Any      any               `cbor:"any"`
	Untagged int
}

func addMarshalCases(add func(string, func() string)) {
	marshal := func(v any) string { return hexOf(cc.Marshal(v)) }
	add("root/marshal/struct-tags", func() string {
		return marshal(goldenTagged{
			Name: "n", IntKey: 7, NegKey: "neg", Wrapped: "http://x", Raw: []byte{9},
			Arr: [4]byte{1, 2, 3, 4}, F32: 1.5, Strs: []string{"b", "a"}, M: map[string]int{"y": 2, "x": 1},
			Any: []any{uint64(1), "two"}, Untagged: 3,
		})
	})
	add("root/marshal/struct-omitempty-zero", func() string { return marshal(goldenTagged{}) })
	add("root/marshal/embedded-struct", func() string { return marshal(GoldenEmbedded{GoldenInner{1, "x"}, 2}) })
	add("root/marshal/embedded-unexported-struct", func() string {
		return marshal(GoldenEmbeddedUnexported{goldenInnerUnexported{1}, 2})
	})
	add("root/marshal/embedded-pointer-struct", func() string {
		return marshal(GoldenEmbeddedPtr{&GoldenInner{1, "x"}, 2})
	})
	add("root/marshal/time-post-1970", func() string { return marshal(time.Unix(1363896240, 0).UTC()) })
	add("root/marshal/time-pre-1970", func() string { return marshal(time.Unix(-10, 0).UTC()) })
	add("root/marshal/time-nanos", func() string { return marshal(time.Unix(1363896240, 500000000).UTC()) })
	add("root/marshal/bigint-small", func() string { return marshal(big.NewInt(1)) })
	add("root/marshal/bigint-large", func() string {
		return marshal(new(big.Int).Lsh(big.NewInt(1), 64))
	})
	add("root/marshal/bigint-negative", func() string { return marshal(big.NewInt(-2)) })
	add("root/marshal/bigint-nil", func() string { return marshal((*big.Int)(nil)) })
	add("root/marshal/map-int-keys", func() string { return marshal(map[int]string{10: "a", -1: "b", 100: "c"}) })
	add("root/marshal/map-string-lenfirst", func() string { return marshal(map[string]int{"aa": 1, "b": 2}) })
	add("root/marshal/nil", func() string { return marshal(nil) })
	add("root/marshal/nil-bytes", func() string { return marshal([]byte(nil)) })
	add("root/marshal/nil-int-slice", func() string { return marshal([]int(nil)) })
	add("root/marshal/negative-int", func() string { return marshal(int64(math.MinInt64)) })
	add("root/marshal/uint64-max", func() string { return marshal(uint64(math.MaxUint64)) })
	add("root/marshal/float32", func() string { return marshal(float32(0.5)) })
	add("root/marshal/value", func() string { return marshal(cc.MakeArray(cc.Uint(1))) })
	add("root/marshal/unsupported-chan", func() string { return marshal(make(chan int)) })
	add("root/marshal/unsupported-func", func() string { return marshal(func() {}) })
	add("root/marshal/canonical-map", func() string {
		return hexOf(cc.New(cc.ModeCanonical).Marshal(map[string]int{"aa": 1, "b": 2}))
	})
	add("root/marshal/ctap2-float", func() string { return hexOf(cc.New(cc.ModeCTAP2).Marshal(1.5)) })
}

func fmtResult(v any, err error) string {
	if err != nil {
		return g.Err(err, rootSentinels)
	}
	return fmt.Sprintf("ok:%T:%v", v, v)
}

func addUnmarshalCases(add func(string, func() string)) {
	into := func(hexIn string, target any) error { return cc.Unmarshal(g.MustHex(hexIn), target) }
	add("root/unmarshal/any-negint-min", func() string {
		var v any
		err := into("3bffffffffffffffff", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-negint-m1", func() string {
		var v any
		err := into("20", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-map-text", func() string {
		var v any
		err := into("a2616201616102", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-map-int-keys", func() string {
		var v any
		err := into("a20a01200b", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-bytes-key", func() string {
		var v any
		err := into("a1410101", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-array-key", func() string {
		var v any
		err := into("a1810101", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-float16", func() string {
		var v any
		err := into("f93c00", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-bytes", func() string {
		var v any
		err := into("43010203", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/any-null", func() string {
		var v any = 1
		err := into("f6", &v)
		return fmtResult(v, err)
	})
	add("root/unmarshal/rawmessage-unsorted-map", func() string {
		var s struct {
			R cc.RawMessage `cbor:"r"`
		}
		err := into("a16172a2616201616102", &s)
		return hexOf([]byte(s.R), err)
	})
	add("root/unmarshal/rawmessage-non-shortest", func() string {
		var s struct {
			R cc.RawMessage `cbor:"r"`
		}
		err := into("a16172821800f93c00", &s) // {"r": [0 (non-shortest), 1.0 (f16)]}
		return hexOf([]byte(s.R), err)
	})
	add("root/unmarshal/struct-tags", func() string {
		var s goldenTagged
		err := into("a4646e616d65616165636f756e740501076177d82068687474703a2f2f78", &s)
		return fmtResult(fmt.Sprintf("%s|%d|%d|%s", s.Name, s.Count, s.IntKey, s.Wrapped), err)
	})
	add("root/unmarshal/struct-tag-mismatch", func() string {
		var s goldenTagged
		err := into("a16177617a", &s)
		return g.OK(err, rootSentinels)
	})
	add("root/unmarshal/struct-unknown-field", func() string {
		var s GoldenInner
		err := into("a36161016162626262627a7a0a", &s)
		return fmtResult(s, err)
	})
	add("root/unmarshal/embedded-struct", func() string {
		var s GoldenEmbedded
		err := into("a3616101616261786163 02", &s)
		return fmtResult(s, err)
	})
	add("root/unmarshal/uint8-overflow", func() string {
		var u uint8
		err := into("19012c", &u)
		return fmtResult(u, err)
	})
	add("root/unmarshal/negint-into-uint", func() string {
		var u uint
		err := into("20", &u)
		return fmtResult(u, err)
	})
	add("root/unmarshal/int64-overflow", func() string {
		var i int64
		err := into("1bffffffffffffffff", &i)
		return fmtResult(i, err)
	})
	add("root/unmarshal/float-into-int", func() string {
		var i int
		err := into("f94100", &i)
		return fmtResult(i, err)
	})
	add("root/unmarshal/text-into-int", func() string {
		var i int
		err := into("6161", &i)
		return fmtResult(i, err)
	})
	add("root/unmarshal/not-pointer", func() string {
		var i int
		return g.OK(cc.Unmarshal(g.MustHex("01"), i), rootSentinels)
	})
	add("root/unmarshal/time-tag1", func() string {
		var tm time.Time
		err := into("c11a514b67b0", &tm)
		return fmtResult(tm.UTC().Format(time.RFC3339Nano), err)
	})
	add("root/unmarshal/time-tag0", func() string {
		var tm time.Time
		err := into("c074323031332d30332d32315432303a30343a30305a", &tm)
		return fmtResult(tm.UTC().Format(time.RFC3339Nano), err)
	})
	add("root/unmarshal/time-untagged", func() string {
		var tm time.Time
		err := into("01", &tm)
		return fmtResult(tm.UTC().Format(time.RFC3339Nano), err)
	})
	add("root/unmarshal/bigint-tag2", func() string {
		var b big.Int
		err := into("c249010000000000000000", &b)
		return fmtResult(b.String(), err)
	})
	add("root/unmarshal/bigint-ptr-tag3", func() string {
		var b *big.Int
		err := into("c34101", &b)
		if err != nil {
			return g.Err(err, rootSentinels)
		}
		return "ok:" + b.String()
	})
	add("root/unmarshal/bigint-from-uint", func() string {
		var b big.Int
		err := into("01", &b)
		return fmtResult(b.String(), err)
	})
	add("root/unmarshal/value-target", func() string {
		var v cc.Value
		err := into("82010a", &v)
		return strOf(cc.DiagnosticValue(v), err)
	})
	add("root/unmarshal/array-into-short-go-array", func() string {
		var a [2]int
		err := into("83010203", &a)
		return fmtResult(a, err)
	})
	add("root/unmarshal/map-into-map-int", func() string {
		var m map[int]string
		err := into("a20a6161206162", &m)
		return fmtResult(m, err)
	})
	add("root/unmarshal/trailing", func() string {
		var i int
		err := into("0101", &i)
		return fmtResult(i, err)
	})
	add("root/unmarshal/strict-decoder-struct", func() string {
		var s GoldenInner
		err := cc.StrictDecoder().Unmarshal(g.MustHex("a2616201616101"), &s)
		return fmtResult(s, err)
	})
}

func addHelperCases(add func(string, func() string)) {
	add("root/time/TimeTo-post-1970", func() string {
		return hexOf(cc.New(cc.ModeCoreDeterministic).Encode(nil, cc.TimeTo(time.Unix(1363896240, 0))))
	})
	add("root/time/TimeTo-pre-1970", func() string {
		return hexOf(cc.New(cc.ModeCoreDeterministic).Encode(nil, cc.TimeTo(time.Unix(-10, 0))))
	})
	add("root/time/TimeToFloat", func() string {
		return hexOf(cc.New(cc.ModeCoreDeterministic).Encode(nil, cc.TimeToFloat(time.Unix(1363896240, 500000000))))
	})
	add("root/time/TimeToString", func() string {
		return hexOf(cc.New(cc.ModeCoreDeterministic).Encode(nil, cc.TimeToString(time.Unix(1363896240, 123).UTC())))
	})
	asTime := func(v cc.Value) string {
		tm, err := cc.AsTime(v)
		if err != nil {
			return g.Err(err, rootSentinels)
		}
		return "ok:" + tm.UTC().Format(time.RFC3339Nano)
	}
	add("root/time/AsTime-uint", func() string { return asTime(cc.MakeTag(1, cc.Uint(1363896240))) })
	add("root/time/AsTime-negint", func() string { return asTime(cc.MakeTag(1, cc.NegInt(9))) })
	add("root/time/AsTime-float", func() string { return asTime(cc.MakeTag(1, cc.Float64(1.5))) })
	add("root/time/AsTime-uint-max", func() string { return asTime(cc.MakeTag(1, cc.Uint(math.MaxUint64))) })
	add("root/time/AsTime-float-huge", func() string { return asTime(cc.MakeTag(1, cc.Float64(1e19))) })
	add("root/time/AsTime-float-nan", func() string { return asTime(cc.MakeTag(1, cc.Float64(math.NaN()))) })
	add("root/time/AsTime-tag0", func() string { return asTime(cc.MakeTag(0, cc.Text("2013-03-21T20:04:00.5Z"))) })
	add("root/time/AsTime-tag0-bad", func() string { return asTime(cc.MakeTag(0, cc.Text("yesterday"))) })
	add("root/time/AsTime-wrong-tag", func() string { return asTime(cc.MakeTag(2, cc.Uint(1))) })
	add("root/time/AsTime-not-tag", func() string { return asTime(cc.Uint(1)) })

	asBig := func(v cc.Value) string {
		b, err := cc.AsBigInt(v)
		if err != nil {
			return g.Err(err, rootSentinels)
		}
		return "ok:" + b.String()
	}
	add("root/bigint/AsBigInt-tag2", func() string { return asBig(cc.MakeTag(2, cc.Bytes([]byte{1, 0}))) })
	add("root/bigint/AsBigInt-tag3", func() string { return asBig(cc.MakeTag(3, cc.Bytes([]byte{1}))) })
	add("root/bigint/AsBigInt-empty", func() string { return asBig(cc.MakeTag(2, cc.Bytes(nil))) })
	add("root/bigint/AsBigInt-uint", func() string { return asBig(cc.Uint(5)) })
	enc := cc.New(cc.ModeCoreDeterministic)
	add("root/bigint/BigIntTo-zero", func() string { return hexOf(enc.Encode(nil, cc.BigIntTo(big.NewInt(0)))) })
	add("root/bigint/BigIntTo-neg1", func() string { return hexOf(enc.Encode(nil, cc.BigIntTo(big.NewInt(-1)))) })
	add("root/bigint/BigIntTo-2p64", func() string {
		return hexOf(enc.Encode(nil, cc.BigIntTo(new(big.Int).Lsh(big.NewInt(1), 64))))
	})
	add("root/bigint/BigIntTo-nil", func() string { return hexOf(enc.Encode(nil, cc.BigIntTo(nil))) })

	add("root/nested/AsNestedCBOR", func() string {
		b, err := cc.AsNestedCBOR(cc.MakeTag(24, cc.Bytes([]byte{1})))
		return hexOf(b, err)
	})
	add("root/nested/AsNestedCBOR-wrong", func() string {
		b, err := cc.AsNestedCBOR(cc.MakeTag(25, cc.Bytes([]byte{1})))
		return hexOf(b, err)
	})
	add("root/map/AsStringMap", func() string {
		m, err := cc.AsStringMap(cc.MakeMap(entry(cc.Text("a"), cc.Uint(1))))
		return fmtResult(len(m), err)
	})
	add("root/map/AsStringMap-nontext", func() string {
		m, err := cc.AsStringMap(cc.MakeMap(entry(cc.Uint(1), cc.Uint(1))))
		return fmtResult(len(m), err)
	})
	add("root/value/clone-independent", func() string {
		orig := cc.MakeArray(cc.Bytes([]byte{1}))
		c := orig.Clone()
		orig.Items[0].Bstr[0] = 2
		return fmt.Sprintf("ok:%d", c.Items[0].Bstr[0])
	})
}

func addRawCases(add func(string, func() string)) {
	add("root/raw/rawmessage-nil-marshal", func() string { return hexOf(cc.RawMessage(nil).MarshalCBOR()) })
	add("root/raw/rawmessage-struct-marshal-unsorted", func() string {
		return hexOf(cc.Marshal(struct {
			R cc.RawMessage `cbor:"r"`
		}{R: g.MustHex("a2616201616102")}))
	})
	add("root/raw/rawmessage-unmarshal-direct", func() string {
		var r cc.RawMessage
		err := r.UnmarshalCBOR(g.MustHex("a2616201616102"))
		return hexOf([]byte(r), err)
	})
	add("root/raw/rawtag-marshal", func() string {
		return hexOf(cc.RawTag{ID: 100, Content: g.MustHex("a2616201616102")}.MarshalCBOR())
	})
	add("root/raw/rawtag-nil-content", func() string { return hexOf(cc.RawTag{ID: 100}.MarshalCBOR()) })
	add("root/raw/rawtag-unmarshal-unsorted", func() string {
		var rt cc.RawTag
		err := rt.UnmarshalCBOR(g.MustHex("d864a2616201616102"))
		return hexOf(append([]byte(fmt.Sprintf("%d:", rt.ID)), rt.Content...), err)
	})
	add("root/raw/rawtag-unmarshal-not-tag", func() string {
		var rt cc.RawTag
		return g.OK(rt.UnmarshalCBOR(g.MustHex("01")), rootSentinels)
	})
}

func addSequenceCases(add func(string, func() string)) {
	diagSeq := func(s cc.Sequence, err error) string {
		if err != nil {
			return g.Err(err, rootSentinels)
		}
		parts := make([]string, len(s))
		for i, v := range s {
			parts[i] = cc.DiagnosticValue(v)
		}
		return "ok:" + strings.Join(parts, ", ")
	}
	add("root/sequence/decode-two", func() string { return diagSeq(cc.DecodeSequence(g.MustHex("0182a1616101f6"))) })
	add("root/sequence/decode-empty", func() string { return diagSeq(cc.DecodeSequence(nil)) })
	add("root/sequence/decode-bad-tail", func() string { return diagSeq(cc.DecodeSequence(g.MustHex("01ff"))) })
	add("root/sequence/decode-truncated", func() string { return diagSeq(cc.DecodeSequence(g.MustHex("011a00"))) })
	add("root/sequence/encode", func() string {
		return hexOf(cc.EncodeSequence(nil, cc.Uint(1), cc.MakeMap(entry(cc.Text("b"), cc.Uint(1)), entry(cc.Text("a"), cc.Uint(2)))))
	})
	add("root/sequence/marshal", func() string { return hexOf(cc.MarshalSequence(1, "a", []int{2})) })
	add("root/sequence/type-marshal", func() string { return hexOf(cc.Sequence{cc.Uint(1), cc.Null()}.MarshalCBOR()) })
	add("root/sequence/type-unmarshal", func() string {
		var s cc.Sequence
		err := s.UnmarshalCBOR(g.MustHex("0102"))
		return diagSeq(s, err)
	})
}

func addStreamCases(add func(string, func() string)) {
	stream := func(mode cc.Mode, steps func(s *cc.StreamEncoder) error) string {
		var buf bytes.Buffer
		s := cc.New(mode).Stream(&buf)
		if err := steps(s); err != nil {
			return g.Err(err, rootSentinels) + "|" + fmt.Sprintf("%x", buf.Bytes())
		}
		if err := s.Flush(); err != nil {
			return g.Err(err, rootSentinels)
		}
		return "hex:" + fmt.Sprintf("%x", buf.Bytes())
	}
	seq := func(fs ...func() error) error {
		for _, f := range fs {
			if err := f(); err != nil {
				return err
			}
		}
		return nil
	}
	add("root/stream/scalars", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error {
			return seq(
				func() error { return s.BeginArray(9) },
				func() error { return s.WriteUint(1000) },
				func() error { return s.WriteNegInt(0) },
				func() error { return s.WriteBytes([]byte{1}) },
				func() error { return s.WriteText("a") },
				func() error { return s.WriteBool(true) },
				func() error { return s.WriteNull() },
				func() error { return s.WriteUndefined() },
				func() error { return s.WriteFloat64(1.5) },
				func() error { return s.WriteFloat32(0.5) },
				func() error { return s.EndContainer() },
			)
		})
	})
	add("root/stream/tag-and-raw", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error {
			return seq(
				func() error { return s.BeginArray(2) },
				func() error { return s.WriteTag(1) },
				func() error { return s.WriteUint(0) },
				func() error { return s.WriteRawCBOR([]byte{0x80}) },
				func() error { return s.EndContainer() },
			)
		})
	})
	add("root/stream/write-value-map", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error {
			return s.WriteValue(cc.MakeMap(entry(cc.Text("b"), cc.Uint(1)), entry(cc.Text("a"), cc.Uint(2))))
		})
	})
	add("root/stream/indefinite-permissive", func() string {
		return stream(cc.ModePermissive, func(s *cc.StreamEncoder) error {
			return seq(
				func() error { return s.BeginArray(-1) },
				func() error { return s.WriteUint(1) },
				func() error { return s.EndContainer() },
			)
		})
	})
	add("root/stream/indefinite-deterministic", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error { return s.BeginMap(-1) })
	})
	add("root/stream/overflow", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error {
			return seq(
				func() error { return s.BeginArray(1) },
				func() error { return s.WriteUint(1) },
				func() error { return s.WriteUint(2) },
			)
		})
	})
	add("root/stream/nested-overflow", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error {
			return seq(
				func() error { return s.BeginArray(1) },
				func() error { return s.BeginArray(0) },
				func() error { return s.EndContainer() },
				func() error { return s.BeginArray(0) },
				func() error { return s.EndContainer() },
				func() error { return s.EndContainer() },
			)
		})
	})
	add("root/stream/deterministic-unsorted-map", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error {
			return seq(
				func() error { return s.BeginMap(2) },
				func() error { return s.WriteText("b") },
				func() error { return s.WriteUint(1) },
				func() error { return s.WriteText("a") },
				func() error { return s.WriteUint(2) },
				func() error { return s.EndContainer() },
			)
		})
	})
	add("root/stream/end-without-container", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error { return s.EndContainer() })
	})
	add("root/stream/underflow", func() string {
		return stream(cc.ModeCoreDeterministic, func(s *cc.StreamEncoder) error {
			return seq(
				func() error { return s.BeginArray(2) },
				func() error { return s.WriteUint(1) },
				func() error { return s.EndContainer() },
			)
		})
	})
	add("root/stream/encode-to", func() string {
		var buf bytes.Buffer
		err := cc.New(cc.ModeCanonical).EncodeTo(&buf, cc.MakeMap(entry(cc.Text("aa"), cc.Uint(1)), entry(cc.Text("b"), cc.Uint(2))))
		return hexOf(buf.Bytes(), err)
	})
	add("root/stream/decode-from", func() string {
		v, err := cc.NewDecoder().DecodeFrom(bytes.NewReader(g.MustHex("8201020304")))
		return strOf(cc.DiagnosticValue(v), err)
	})
	add("root/stream/iterator", func() string {
		st := cc.NewDecoder().Stream(bytes.NewReader(g.MustHex("0102ff")))
		var parts []string
		for st.Next() {
			parts = append(parts, cc.DiagnosticValue(st.Value()))
		}
		return strOf(strings.Join(parts, ","), st.Err())
	})
}
