// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"
	"sync"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

type Mode int

const (
	ModePermissive        Mode = iota
	ModeCoreDeterministic Mode = iota
	ModeCanonical         Mode = iota
	ModeCTAP2             Mode = iota

	// ModePreferredPlus is Experimental: it implements the preferred-plus
	// serialization of draft-ietf-cbor-serialization-13 §4 (shortest
	// arguments and floats, NaN as f97e00, preferred bignums, definite
	// lengths) while keeping map entries in insertion order. The name and
	// rules are provisional until the draft is published as an RFC
	// (proposal 034, Draft class). Go maps marshaled in this mode follow
	// Go's map iteration order and are therefore not deterministic.
	ModePreferredPlus Mode = iota
)

// maxMode is the highest valid Mode.
const maxMode = ModePreferredPlus

type encodeConfig struct {
	allowNonFiniteFloats bool
	allowInvalidUTF8     bool
	legacyBignum         bool
	bufferPool           *sync.Pool
	invalidUTF8          rfc8949.InvalidUTF8
	goNames              bool // WithGoFieldNames (proposal 025)
}

type Option func(*encodeConfig)

func AllowNonFiniteFloats() Option {
	return func(c *encodeConfig) { c.allowNonFiniteFloats = true }
}

// AllowInvalidUTF8 writes text that is not valid UTF-8 as a text string
// unchanged, which is not conformant (RFC 8949 §3.1). It is the same as
// WithInvalidUTF8(InvalidUTF8Allow).
func AllowInvalidUTF8() Option {
	return WithInvalidUTF8(InvalidUTF8Allow)
}

// WithInvalidUTF8 selects how the encoder writes text that is not valid
// UTF-8 (proposal 035): InvalidUTF8Reject (the default) returns
// ErrInvalidUTF8; InvalidUTF8Allow writes it unchanged (not conformant);
// InvalidUTF8Replace substitutes U+FFFD for each invalid byte;
// InvalidUTF8Lossless writes conformant CBOR that keeps the exact bytes
// (tag 273 for WTF-8, otherwise a byte string). Valid UTF-8 is written
// the same way under every policy. The policy applies to every text
// string, including map keys; in deterministic modes, keys sort by the
// bytes actually written and duplicates are rejected.
func WithInvalidUTF8(p InvalidUTF8) Option {
	return func(c *encodeConfig) {
		c.invalidUTF8 = p
		c.allowInvalidUTF8 = p == InvalidUTF8Allow
	}
}

// WithLegacyBignumPassthrough makes deterministic modes emit tag 2/3
// bignum contents as supplied, as v0.2.2 did. By default deterministic
// modes write the RFC 8949 §3.4.3 preferred form: leading zeros
// stripped, and values that fit 64 bits as plain integers.
//
// Deprecated: v0.2 compatibility only (proposal 024); removed no
// earlier than v0.32.0.
func WithLegacyBignumPassthrough() Option {
	return func(c *encodeConfig) { c.legacyBignum = true }
}

// CompatV02 applies every encoder selector needed to reproduce v0.2.x
// output: currently WithLegacyBignumPassthrough. It exists to unblock
// upgrades, not as a long-term mode (proposal 034).
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02() Option {
	return func(c *encodeConfig) { c.legacyBignum = true }
}

// WithBufferPool makes Encode build output in a scratch buffer taken
// from p, which should hold *[]byte values. A nil or mistyped value from
// p is replaced with a fresh buffer instead of panicking.
func WithBufferPool(p *sync.Pool) Option {
	return func(c *encodeConfig) { c.bufferPool = p }
}

type Encoder struct {
	mode      Mode
	cfg       encodeConfig
	sortCache rfc8949.SortStateCache
	shared    bool
}

// New returns an Encoder with a goroutine-local sort cache. The returned
// encoder is NOT safe for concurrent use from multiple goroutines; use
// NewShared for encoders shared across goroutines. Package-level
// Marshal is safe for concurrent use.
func New(mode Mode, opts ...Option) *Encoder {
	cfg := encodeConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	return &Encoder{mode: mode, cfg: cfg}
}

// NewShared returns an Encoder safe for concurrent use from multiple
// goroutines. It omits the goroutine-local sort cache, falling back to
// sync.Pool for deterministic map encoding. Use for package-level
// singletons shared across goroutines.
func NewShared(mode Mode, opts ...Option) *Encoder {
	cfg := encodeConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	return &Encoder{mode: mode, cfg: cfg, shared: true}
}

func (e *Encoder) Encode(dst []byte, v cbor.Value) ([]byte, error) {
	if e.mode < ModePermissive || e.mode > maxMode {
		return dst, fmt.Errorf("%w: %d", cbor.ErrInvalidMode, e.mode)
	}
	opts := e.encodeOpts()
	if e.cfg.bufferPool != nil {
		bp, ok := e.cfg.bufferPool.Get().(*[]byte)
		if !ok || bp == nil {
			b := make([]byte, 0, 512)
			bp = &b
		}
		buf := (*bp)[:0]
		buf, err := rfc8949.Encode(buf, v, opts)
		if err != nil {
			*bp = buf
			e.cfg.bufferPool.Put(bp)
			return dst, err
		}
		dst = append(dst, buf...)
		*bp = buf
		e.cfg.bufferPool.Put(bp)
		return dst, nil
	}
	return rfc8949.Encode(dst, v, opts)
}

func (e *Encoder) encodeOpts() rfc8949.EncodeOpts {
	opts := rfc8949.EncodeOpts{
		AllowNonFiniteFloats: e.cfg.allowNonFiniteFloats,
		AllowInvalidUTF8:     e.cfg.allowInvalidUTF8,
		InvalidUTF8:          e.cfg.invalidUTF8,

		LegacyBignumPassthrough: e.cfg.legacyBignum, //nolint:staticcheck // plumbing for the deprecated WithLegacyBignumPassthrough selector
	}
	if !e.shared {
		opts.SortCache = &e.sortCache
	}
	switch e.mode {
	case ModePermissive:
		opts.FloatMode = rfc8949.FloatPreserve
	case ModeCoreDeterministic:
		opts.Deterministic = true
		opts.SortMode = rfc8949.SortBytewiseLex
		opts.FloatMode = rfc8949.FloatShortest
	case ModeCanonical:
		opts.Deterministic = true
		opts.SortMode = rfc8949.SortLengthFirst
		opts.FloatMode = rfc8949.FloatShortest
	case ModeCTAP2:
		opts.Deterministic = true
		opts.SortMode = rfc8949.SortLengthFirst
		opts.FloatMode = rfc8949.FloatForce64
	case ModePreferredPlus:
		opts.Deterministic = true
		opts.SortMode = rfc8949.SortNone
		opts.FloatMode = rfc8949.FloatShortest
	}
	return opts
}
