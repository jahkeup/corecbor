// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"
	"reflect"

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
		return unsupportedTarget(cbor.KindInvalid, reflect.TypeFor[*RawMessage](), "UnmarshalCBOR on nil *RawMessage")
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

// UnmarshalCBOR stores the tag number and the tag content's original
// bytes. data must be exactly one well-formed tagged item; leading
// self-describe tags (55799) are skipped, as Decode does.
func (t *RawTag) UnmarshalCBOR(data []byte) error {
	if t == nil {
		return unsupportedTarget(cbor.KindInvalid, reflect.TypeFor[*RawTag](), "UnmarshalCBOR on nil *RawTag")
	}
	dec := NewDecoder()
	val, err := dec.Decode(data)
	if err != nil {
		return fmt.Errorf("cbor: RawTag decode: %w", err)
	}
	if val.Kind != cbor.KindTag {
		return typeMismatchf(val.Kind, reflect.TypeFor[RawTag](), "RawTag expected Tag, got kind %d", val.Kind)
	}
	item := stripSelfDescribe(data)
	h := wire.ParseHead(item)
	t.ID = h.Arg
	t.Content = append(RawMessage(nil), item[h.N:]...)
	return nil
}
