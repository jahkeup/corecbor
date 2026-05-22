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
)

type encodeConfig struct {
	allowNonFiniteFloats bool
	allowInvalidUTF8     bool
	bufferPool           *sync.Pool
}

type Option func(*encodeConfig)

func AllowNonFiniteFloats() Option {
	return func(c *encodeConfig) { c.allowNonFiniteFloats = true }
}

func AllowInvalidUTF8() Option {
	return func(c *encodeConfig) { c.allowInvalidUTF8 = true }
}

func WithBufferPool(p *sync.Pool) Option {
	return func(c *encodeConfig) { c.bufferPool = p }
}

type Encoder struct {
	mode      Mode
	cfg       encodeConfig
	sortCache rfc8949.SortStateCache
}

func New(mode Mode, opts ...Option) *Encoder {
	cfg := encodeConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	return &Encoder{mode: mode, cfg: cfg}
}

func (e *Encoder) Encode(dst []byte, v cbor.Value) ([]byte, error) {
	if e.mode < ModePermissive || e.mode > ModeCTAP2 {
		return dst, fmt.Errorf("%w: %d", cbor.ErrInvalidMode, e.mode)
	}
	opts := e.encodeOpts()
	if e.cfg.bufferPool != nil {
		bp := e.cfg.bufferPool.Get().(*[]byte)
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
		SortCache:            &e.sortCache,
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
	}
	return opts
}
