// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/decerr"
	"github.com/jahkeup/corecbor/rfc8949"
)

type decodeConfig struct {
	opts            rfc8949.DecodeOpts
	noInternalArena bool
	maxItemSize     int  // WithMaxItemSize: 0 default, < 0 none
	textLossless    bool // InvalidUTF8Lossless: Unmarshal into string accepts non-UTF-8 forms

	// RequireDeterministic's NaN rule, applied when
	// the Decoder is built so option order doesn't matter.
	deterministicNaN bool
	allowNaNPayloads bool

	// Reflection options.
	disallowUnknown     bool
	disallowDroppedTags bool
	disallowUndefined   bool
	caseInsensitive     bool
	legacyNoTextBinary  bool
}

type DecoderOption func(*decodeConfig)

func RejectIndefiniteLength() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectIndefiniteLength = true }
}

func RejectNonShortest() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectNonShortest = true }
}

// RejectInvalidUTF8 rejects text strings that are not valid UTF-8 with
// ErrInvalidUTF8. It is the same as
// WithInvalidUTF8Decoding(InvalidUTF8Reject).
func RejectInvalidUTF8() DecoderOption {
	return WithInvalidUTF8Decoding(InvalidUTF8Reject)
}

// WithInvalidUTF8Decoding selects how the decoder handles text strings
// that are not valid UTF-8:
//   - InvalidUTF8Allow (the default) keeps their bytes unchanged;
//   - InvalidUTF8Reject returns ErrInvalidUTF8;
//   - InvalidUTF8Replace substitutes U+FFFD for each invalid byte,
//     including in map keys and indefinite-length text;
//   - InvalidUTF8Lossless keeps text bytes unchanged and also lets
//     Unmarshal into a Go string accept the lossless encoder forms: a
//     byte string, or tag 272/273/274 around one, stored with its exact
//     bytes.
//
// The last of RejectInvalidUTF8 and WithInvalidUTF8Decoding wins.
func WithInvalidUTF8Decoding(p InvalidUTF8) DecoderOption {
	return func(c *decodeConfig) {
		c.opts.RejectInvalidUTF8 = p == InvalidUTF8Reject
		c.opts.ReplaceInvalidUTF8 = p == InvalidUTF8Replace
		c.textLossless = p == InvalidUTF8Lossless
	}
}

func RejectDuplicateMapKeys() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectDuplicateMapKeys = true }
}

// RejectUnknownTags rejects every tag not in the allowlist built by
// WithAllowedTags. With no WithAllowedTags option, the allowlist is
// TagsModeled: the tags encoder-decoder-spec.md §4.3 says the library
// models. Tag 55799 (self-describe) is always allowed.
func RejectUnknownTags() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectUnknownTags = true }
}

// WithAllowedTags restricts the tags the decoder accepts to ids (plus
// any added by other WithAllowedTags options). A tag not in the set
// fails with ErrUnknownTag. Tag 55799 (self-describe) is always
// allowed, so WithAllowedTags with no arguments allows only 55799.
func WithAllowedTags(ids ...uint64) DecoderOption {
	return func(c *decodeConfig) {
		c.opts.RejectUnknownTags = true
		all := append(c.opts.AllowedTags.IDs(), ids...)
		c.opts.AllowedTags = rfc8949.NewTagSet(append(all, cbor.TagSelfDescribe)...)
	}
}

// WithErrorPath makes decoder errors carry DecodeError.Path, the
// RFC 9535-style location of the offending item, e.g. `$[1].k` or
// `$["a b"][0]`. The path is appended to the message as " (path)".
// Off by default; it costs nothing until an error occurs.
func WithErrorPath() DecoderOption {
	return func(c *decodeConfig) { c.opts.ErrorPath = true }
}

// TagsModeled is the default allowlist for RejectUnknownTags: exactly
// the tags in encoder-decoder-spec.md §4.3.
var TagsModeled = []uint64{0, 1, 2, 3, 21, 22, 23, 24, 32, 35, 258, 55799}

// TagsWellKnown is TagsModeled plus the tags of the COSE/CWT/EAT
// family this module tree implements. It is never applied implicitly;
// pass WithAllowedTags(TagsWellKnown...) to use it.
var TagsWellKnown = []uint64{
	0, 1, 2, 3, // RFC 8949 §3.4.1–3.4.3
	21, 22, 23, // expected conversion
	24,     // encoded CBOR
	32, 35, // URI, regexp
	258,        // set
	16, 17, 18, // COSE_Encrypt0, COSE_Mac0, COSE_Sign1 (RFC 9052)
	96, 97, 98, // COSE_Encrypt, COSE_Mac, COSE_Sign
	61,    // CWT (RFC 8392)
	601,   // UCCS (RFC 9781)
	602,   // detached EAT bundle (RFC 9711 §5)
	55799, // self-describe
}

func RejectNonFiniteFloats() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectNonFiniteFloats = true }
}

// RejectInvalidTagContent rejects a tag whose content is not valid for
// it (RFC 8949 §3.4, §5.3.2) with an error wrapping ErrMalformedTag:
// tag 2 around a text string, tag 0 around an integer or a string that
// isn't an RFC 3339 date/time, tag 24 around bytes that aren't one
// well-formed item, base64 text with bad padding (tags 33, 34), an
// RFC 8746 typed array whose length isn't a multiple of its element
// size, and so on for the tags RFC 8949 §3.4 defines, the modeled tags
// (TagsModeled) and the typed arrays. Other tags accept any content.
// StrictDecoder and DeterministicDecoder include it.
func RejectInvalidTagContent() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectInvalidTagContent = true }
}

func RejectNullMapKeys() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectNullMapKeys = true }
}

// KeyIdentity selects when two map keys are the same key for duplicate
// handling: KeyIdentityValue (RFC 8949 §5.6.1 data model, the default)
// or KeyIdentityEncoded (identical encoded bytes).
type KeyIdentity = rfc8949.KeyIdentity

const (
	// KeyIdentityValue compares keys in the CBOR data model (RFC 8949
	// §5.6.1 + erratum 8589): 01 and 1800 are the same key, as are
	// f93c00 and fa3f800000; integer 1 and float 1.0 are not. Default.
	KeyIdentityValue = rfc8949.KeyIdentityValue
	// KeyIdentityEncoded treats keys as the same only when their encoded
	// bytes are identical: 01 and 1800 are different keys.
	KeyIdentityEncoded = rfc8949.KeyIdentityEncoded
)

// WithMapKeyIdentity selects key identity for duplicate detection.
// It applies to every duplicate policy: last-write-wins (default),
// RejectDuplicateMapKeys, and KeepDuplicateMapKeys (which keeps all).
// Every map size uses the same rule.
func WithMapKeyIdentity(k KeyIdentity) DecoderOption {
	return func(c *decodeConfig) { c.opts.KeyIdentity = k }
}

// KeepDuplicateMapKeys keeps every map entry, in input order, instead
// of resolving repeated keys last-write-wins. Use a Value or
// []MapEntry target to see them: Unmarshal into a Go map still assigns
// the last one last. Combining it with RejectDuplicateMapKeys makes
// every decode fail with ErrInvalidOption.
func KeepDuplicateMapKeys() DecoderOption {
	return func(c *decodeConfig) { c.opts.KeepDuplicateMapKeys = true }
}

// WithLegacyFloatKeyEquality compares float map keys as v0.2.2 did
// (same kind and ==, so NaN keys never repeat and 1.0 at different
// widths are different keys) instead of per RFC 8949 §5.6.1 and
// erratum 8589.
//
// Deprecated: v0.2 compatibility only; removed no
// earlier than v0.5.0.
func WithLegacyFloatKeyEquality() DecoderOption {
	return func(c *decodeConfig) { c.opts.LegacyFloatKeyEquality = true }
}

// CompatV02Decoding applies every decoder selector needed to reproduce
// v0.2.x results: WithLegacyFloatKeyEquality and
// WithLegacyNoTextBinaryUnmarshal.
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.5.0.
func CompatV02Decoding() DecoderOption {
	return func(c *decodeConfig) {
		c.opts.LegacyFloatKeyEquality = true
		c.legacyNoTextBinary = true
	}
}

// RequireDeterministic rejects input that is not RFC 8949 §4.2.1 Core
// Deterministic: non-preferred serialization (§4.1, §3.4.3: shortest
// arguments and float widths, definite lengths, preferred bignums) and
// maps whose keys are not in strictly increasing bytewise-lex order of
// their encodings (which also rejects duplicates). Errors wrap
// ErrNotDeterministic, or ErrNotPreferred for serialization violations
// (together with ErrNonShortest or ErrIndefiniteLength where they
// apply).
//
// A NaN is accepted only as f97e00, the one NaN the deterministic
// encoders write (RFC 8949 §4.2.2 leaves NaN handling to the
// application), so that re-encoding accepted input reproduces it.
// AllowNaNPayloads restores the §4.2.1 rule alone:
// any NaN in the shortest width that keeps its payload and sign.
func RequireDeterministic() DecoderOption {
	return func(c *decodeConfig) {
		c.opts.RequirePreferred = true
		c.opts.RequireSortedMapKeys = true
		c.deterministicNaN = true
	}
}

// AllowNaNPayloads makes RequireDeterministic accept a NaN with any
// payload and sign in the shortest width that preserves them, which is
// all RFC 8949 §4.2.1 asks, instead of only f97e00. Input it lets
// through can't be reproduced by re-encoding in a deterministic mode,
// which writes every NaN as f97e00. It doesn't relax
// RequirePreferredPlus, whose rule is f97e00 only, or
// RejectNonFiniteFloats (set by StrictDecoder and DeterministicDecoder),
// which rejects every NaN.
func AllowNaNPayloads() DecoderOption {
	return func(c *decodeConfig) { c.allowNaNPayloads = true }
}

// RequirePreferredPlus is Experimental: it implements the checking
// decoder of draft-ietf-cbor-serialization-13 (§4, Appendix G) and is
// provisional until the draft is published.
// It rejects input that is not preferred-plus serialized: non-shortest
// arguments (including float width: a value encodable exactly in a
// narrower float must use it), indefinite lengths, NaN other than
// f97e00, and bignums with leading zeros or that fit major 0/1. Errors
// wrap ErrNotPreferred.
func RequirePreferredPlus() DecoderOption {
	return func(c *decodeConfig) {
		c.opts.RequirePreferred = true
		c.opts.RequireCanonicalNaN = true
	}
}

func WithMaxNestingDepth(n int) DecoderOption {
	return func(c *decodeConfig) { c.opts.MaxNestingDepth = n }
}

func WithMaxArrayLength(n int) DecoderOption {
	return func(c *decodeConfig) { c.opts.MaxArrayLength = n }
}

func WithMaxByteStringLength(n int) DecoderOption {
	return func(c *decodeConfig) { c.opts.MaxByteStringLength = n }
}

// DefaultMaxItemSize is the default limit on the encoded size of one
// item that DecodeFrom or Stream reads: 64 MiB.
const DefaultMaxItemSize = rfc8949.DefaultMaxItemSize

// WithMaxItemSize limits the encoded size of one item read from an
// io.Reader by Decoder.DecodeFrom or a Stream to n bytes. An item over
// the limit returns an error wrapping ErrMaxItemSize as soon as a head
// shows it, before its bytes are read. The default (n == 0) is
// DefaultMaxItemSize, so reading is bounded even without a memory
// budget; a negative n removes the limit, leaving only the per-string,
// per-container and nesting limits (and WithMemoryBudget, if set). It
// doesn't apply to Decode, whose input is already in memory.
func WithMaxItemSize(n int) DecoderOption {
	return func(c *decodeConfig) { c.maxItemSize = n }
}

// WithMemoryBudget sets a global allocation budget (in bytes) for a
// single decode operation. Returns ErrMemoryBudgetExceeded when
// cumulative allocations exceed the limit. A limit of 0 disables
// tracking (the default).
func WithMemoryBudget(limit int) DecoderOption {
	return func(c *decodeConfig) {
		if limit > 0 {
			c.opts.Budget = rfc8949.NewBudget(limit)
		}
	}
}

// WithStringIntern configures the decoder to deduplicate decoded text
// strings through the provided interner. Repeated keys (common in
// stream decode of repetitive schemas) are returned without allocation
// once seen.
func WithStringIntern(si *rfc8949.StringInterner) DecoderOption {
	return func(c *decodeConfig) { c.opts.Interner = si }
}

// WithArena configures the decoder to allocate container backing
// ([]Value for arrays and tag content, []MapEntry for maps) from the
// provided arena instead of the heap. Call arena.Reset() between decode
// operations.
func WithArena(a *rfc8949.Arena) DecoderOption {
	return func(c *decodeConfig) { c.opts.Arena = a }
}

// WithZeroCopy configures the decoder to return byte strings and text
// strings as views into the source buffer rather than copies. The
// caller MUST NOT mutate src after decode, and MUST NOT use decoded
// Values after src is freed or reused.
func WithZeroCopy() DecoderOption {
	return func(c *decodeConfig) { c.opts.ZeroCopy = true }
}

// WithoutInternalArena disables the decoder's internal arena. By default,
// the Decoder uses an auto-managed arena that is reset on each Decode()
// call, meaning decoded Values are valid only until the NEXT Decode() on
// the same decoder. Use this option when Values must outlive the decode
// call (e.g., accumulating into a slice, passing to another goroutine).
func WithoutInternalArena() DecoderOption {
	return func(c *decodeConfig) { c.noInternalArena = true }
}

// Decoder decodes CBOR. A Decoder with its internal arena (the default)
// is NOT safe for concurrent use, and the Values returned by Decode are
// valid only until the next Decode on the same Decoder. Construct with
// WithoutInternalArena() for a Decoder whose results outlive the call.
// Decoder.Unmarshal always stores values independent of the arena, and
// package-level Unmarshal is safe for concurrent use.
type Decoder struct {
	cfg   decodeConfig
	arena *rfc8949.Arena // internal, auto-managed (nil when disabled)
}

func NewDecoder(opts ...DecoderOption) *Decoder {
	return newDecoder(decodeConfig{}, opts)
}

// newDecoder applies opts over cfg and builds the Decoder.
func newDecoder(cfg decodeConfig, opts []DecoderOption) *Decoder {
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.deterministicNaN && !cfg.allowNaNPayloads {
		cfg.opts.RequireCanonicalNaN = true
	}
	d := &Decoder{cfg: cfg}
	if !cfg.noInternalArena && cfg.opts.Arena == nil {
		d.arena = rfc8949.NewArena(256, 64)
	}
	return d
}

// StrictDecoder returns a Decoder with the encoder-decoder-spec.md §3.2
// strict preset: it rejects indefinite lengths, non-shortest arguments,
// invalid UTF-8, duplicate map keys, non-finite floats, null map keys
// and invalid tag content (RejectInvalidTagContent). Tags are accepted;
// add RejectUnknownTags() or WithAllowedTags for closed-world tag
// validation.
func StrictDecoder(opts ...DecoderOption) *Decoder {
	return newDecoder(decodeConfig{opts: rfc8949.StrictOpts()}, opts)
}

// DeterministicDecoder returns StrictDecoder plus RequireDeterministic:
// a decoder that accepts only RFC 8949 §4.2.1 Core Deterministic input.
// Use it where re-encoding must reproduce the received bytes, such as
// inputs bound into signatures or AAD. StrictDecoder itself keeps its
// documented knob list and still accepts unsorted maps.
func DeterministicDecoder(opts ...DecoderOption) *Decoder {
	return StrictDecoder(append([]DecoderOption{RequireDeterministic()}, opts...)...)
}

// Cursor is a forward-only reader over a CBOR byte slice that reads
// item heads and skips payloads until asked to decode. Use
// Decoder.Cursor to obtain one configured with a decoder's options.
type Cursor = rfc8949.Cursor

// Cursor returns a Cursor over src that applies d's strictness knobs
// and limits. Byte slices it returns (Raw, DecodeRaw, Bytes) alias src.
func (d *Decoder) Cursor(src []byte) *Cursor {
	return rfc8949.NewCursor(src, d.cfg.opts)
}

// DecodePrefix decodes the first complete CBOR data item in src and
// returns it together with the unconsumed remainder. Unlike Decode,
// trailing bytes are not an error. The item's source bytes are
// src[:len(src)-len(rest)]; rest aliases src.
func (d *Decoder) DecodePrefix(src []byte) (v Value, rest []byte, err error) {
	v, n, err := d.decode(src)
	if err != nil {
		return cbor.Value{}, nil, err
	}
	return v, src[n:], nil
}

// DecodeRaw is Decode plus the exact source bytes of the item, which
// is all of src on success. Those bytes are what a signature or hash
// over "the item as received" must cover; raw aliases src.
func (d *Decoder) DecodeRaw(src []byte) (v Value, raw []byte, err error) {
	v, err = d.Decode(src)
	if err != nil {
		return cbor.Value{}, nil, err
	}
	return v, src, nil
}

// decode decodes one item from the start of src, resetting per-call
// state (budget, internal arena), and returns the bytes consumed.
func (d *Decoder) decode(src []byte) (cbor.Value, int, error) {
	d.resetBudget()
	opts := d.cfg.opts
	if d.arena != nil {
		d.arena.Reset()
		opts.Arena = d.arena
	}
	return rfc8949.Decode(src, opts)
}

func (d *Decoder) Decode(src []byte) (cbor.Value, error) {
	v, n, err := d.decode(src)
	if err != nil {
		return cbor.Value{}, err
	}
	if n != len(src) {
		return cbor.Value{}, decerr.Text(cbor.ErrTrailingBytes, n, "decode: "+cbor.ErrTrailingBytes.Error())
	}
	return v, nil
}
