// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

type decodeConfig struct {
	opts rfc8949.DecodeOpts
}

type DecoderOption func(*decodeConfig)

func RejectIndefiniteLength() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectIndefiniteLength = true }
}

func RejectNonShortest() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectNonShortest = true }
}

func RejectInvalidUTF8() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectInvalidUTF8 = true }
}

func RejectDuplicateMapKeys() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectDuplicateMapKeys = true }
}

func RejectUnknownTags() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectUnknownTags = true }
}

func RejectNonFiniteFloats() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectNonFiniteFloats = true }
}

func RejectNullMapKeys() DecoderOption {
	return func(c *decodeConfig) { c.opts.RejectNullMapKeys = true }
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
// ([]Value for arrays, []MapEntry for maps) from the provided arena
// instead of the heap. Call arena.Reset() between decode operations.
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

type Decoder struct {
	cfg decodeConfig
}

func NewDecoder(opts ...DecoderOption) *Decoder {
	cfg := decodeConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	return &Decoder{cfg: cfg}
}

func StrictDecoder(opts ...DecoderOption) *Decoder {
	cfg := decodeConfig{opts: rfc8949.StrictOpts()}
	for _, o := range opts {
		o(&cfg)
	}
	return &Decoder{cfg: cfg}
}

func (d *Decoder) Decode(src []byte) (cbor.Value, error) {
	if d.cfg.opts.Budget != nil {
		d.cfg.opts.Budget.Allocated = 0
	}
	v, n, err := rfc8949.Decode(src, d.cfg.opts)
	if err != nil {
		return cbor.Value{}, err
	}
	if n != len(src) {
		return cbor.Value{}, fmt.Errorf("decode: %w", cbor.ErrTrailingBytes)
	}
	return v, nil
}
