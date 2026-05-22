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
	v, n, err := rfc8949.Decode(src, d.cfg.opts)
	if err != nil {
		return cbor.Value{}, err
	}
	if n != len(src) {
		return cbor.Value{}, fmt.Errorf("decode: %w", cbor.ErrTrailingBytes)
	}
	return v, nil
}
