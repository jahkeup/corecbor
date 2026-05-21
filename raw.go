package corecbor

import (
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/wire"
)

// RawMessage is pre-encoded CBOR bytes. It implements Marshaler and
// Unmarshaler by passing bytes through without re-encoding.
// This is the CBOR equivalent of json.RawMessage.
type RawMessage []byte

func (r RawMessage) MarshalCBOR() ([]byte, error) {
	if r == nil {
		enc := New(ModeCoreDeterministic)
		return enc.Encode(nil, cbor.Null{})
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

// RawTag is a CBOR tagged value where the caller controls both the
// tag ID and the raw encoding of the inner content.
type RawTag struct {
	ID      uint64
	Content RawMessage
}

func (t RawTag) MarshalCBOR() ([]byte, error) {
	if t.Content == nil {
		enc := New(ModeCoreDeterministic)
		return enc.Encode(nil, cbor.Tag{ID: t.ID, Inner: cbor.Null{}})
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
	tag, ok := val.(cbor.Tag)
	if !ok {
		return fmt.Errorf("cbor: RawTag expected Tag, got %T", val)
	}
	t.ID = tag.ID
	enc := New(ModeCoreDeterministic)
	inner, err := enc.Encode(nil, tag.Inner)
	if err != nil {
		return fmt.Errorf("cbor: RawTag encode inner: %w", err)
	}
	t.Content = inner
	return nil
}
