// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

type RawMessage []byte

func (r RawMessage) MarshalCBOR() ([]byte, error) {
	if r == nil {
		enc := New(ModeCoreDeterministic)
		return enc.Encode(nil, cbor.Null())
	}
	return []byte(r), nil
}

func (r *RawMessage) UnmarshalCBOR(data []byte) error {
	if r == nil {
		return fmt.Errorf("cbor: UnmarshalCBOR on nil *RawMessage")
	}
	*r = append((*r)[:0], data...)
	return nil
}

type RawTag struct {
	ID      uint64
	Content RawMessage
}

func (t RawTag) MarshalCBOR() ([]byte, error) {
	if t.Content == nil {
		enc := New(ModeCoreDeterministic)
		return enc.Encode(nil, cbor.MakeTag(t.ID, cbor.Null()))
	}
	head := wire.AppendHead(nil, wire.MajorTag, t.ID)
	return append(head, t.Content...), nil
}

func (t *RawTag) UnmarshalCBOR(data []byte) error {
	if t == nil {
		return fmt.Errorf("cbor: UnmarshalCBOR on nil *RawTag")
	}
	dec := NewDecoder()
	val, err := dec.Decode(data)
	if err != nil {
		return fmt.Errorf("cbor: RawTag decode: %w", err)
	}
	if val.Kind != cbor.KindTag {
		return fmt.Errorf("cbor: RawTag expected Tag, got kind %d", val.Kind)
	}
	t.ID = val.TagID()
	enc := New(ModeCoreDeterministic)
	inner, err := enc.Encode(nil, val.TagInner())
	if err != nil {
		return fmt.Errorf("cbor: RawTag encode inner: %w", err)
	}
	t.Content = inner
	return nil
}
