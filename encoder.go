package corecbor

import (
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

type Mode int

const (
	ModePermissive        Mode = iota
	ModeCoreDeterministic Mode = iota
)

type encodeConfig struct {
	allowNonFiniteFloats bool
	allowInvalidUTF8     bool
}

type Option func(*encodeConfig)

func AllowNonFiniteFloats() Option {
	return func(c *encodeConfig) { c.allowNonFiniteFloats = true }
}

func AllowInvalidUTF8() Option {
	return func(c *encodeConfig) { c.allowInvalidUTF8 = true }
}

type Encoder struct {
	mode Mode
	cfg  encodeConfig
}

func New(mode Mode, opts ...Option) *Encoder {
	cfg := encodeConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	return &Encoder{mode: mode, cfg: cfg}
}

func (e *Encoder) Encode(dst []byte, v cbor.Value) ([]byte, error) {
	opts := rfc8949.EncodeOpts{
		AllowNonFiniteFloats: e.cfg.allowNonFiniteFloats,
		AllowInvalidUTF8:     e.cfg.allowInvalidUTF8,
	}
	switch e.mode {
	case ModePermissive:
		return rfc8949.Encode(dst, v, opts)
	case ModeCoreDeterministic:
		return rfc8949.EncodeDeterministic(dst, v, opts)
	default:
		return dst, fmt.Errorf("encode: %w", cbor.ErrInvalidMode)
	}
}
