// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"time"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/internal/rawvalue"
	"github.com/jahkeup/corecbor/rfc8949"
)

var (
	valueType     = reflect.TypeFor[cbor.Value]()
	timeType      = reflect.TypeFor[time.Time]()
	bigIntType    = reflect.TypeFor[big.Int]()
	bigIntPtrType = reflect.TypeFor[*big.Int]()
)

// marshalOpts is what reflection needs from the encoder: its encode
// options plus reflection-only settings.
type marshalOpts struct {
	rfc8949.EncodeOpts
	goNames bool // WithGoFieldNames
}

func goToValue(v any, opts *marshalOpts) (cbor.Value, error) {
	if v == nil {
		return cbor.Null(), nil
	}
	if val, ok := v.(cbor.Value); ok {
		return val, nil
	}
	return reflectToValue(reflect.ValueOf(v), opts)
}

func reflectToValue(rv reflect.Value, opts *marshalOpts) (cbor.Value, error) {
	if !rv.IsValid() {
		return cbor.Null(), nil
	}

	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return cbor.Null(), nil
		}
		rv = rv.Elem()
	}

	if rv.Type() == valueType {
		return rv.Interface().(cbor.Value), nil
	}

	if rv.CanInterface() {
		iface := rv.Interface()
		if m, ok := iface.(Marshaler); ok {
			return marshalerToValue(m, opts)
		}
		if rv.CanAddr() {
			if m, ok := rv.Addr().Interface().(Marshaler); ok {
				return marshalerToValue(m, opts)
			}
		}
	}

	switch rv.Type() {
	case timeType:
		return timeToValue(rv.Interface().(time.Time)), nil
	case bigIntType:
		bi := rv.Interface().(big.Int)
		return cbor.BigIntTo(&bi), nil
	case bigIntPtrType:
		bi := rv.Interface().(*big.Int)
		if bi == nil {
			return cbor.Null(), nil
		}
		return cbor.BigIntTo(bi), nil
	}

	if rv.CanInterface() {
		if m, ok := rv.Interface().(encoding.BinaryMarshaler); ok {
			data, err := m.MarshalBinary()
			if err != nil {
				return cbor.Value{}, fmt.Errorf("cbor: BinaryMarshaler: %w", err)
			}
			return cbor.Bytes(data), nil
		}
		if rv.CanAddr() {
			if m, ok := rv.Addr().Interface().(encoding.BinaryMarshaler); ok {
				data, err := m.MarshalBinary()
				if err != nil {
					return cbor.Value{}, fmt.Errorf("cbor: BinaryMarshaler: %w", err)
				}
				return cbor.Bytes(data), nil
			}
		}
		if m, ok := rv.Interface().(encoding.TextMarshaler); ok {
			data, err := m.MarshalText()
			if err != nil {
				return cbor.Value{}, fmt.Errorf("cbor: TextMarshaler: %w", err)
			}
			return cbor.Text(string(data)), nil
		}
		if rv.CanAddr() {
			if m, ok := rv.Addr().Interface().(encoding.TextMarshaler); ok {
				data, err := m.MarshalText()
				if err != nil {
					return cbor.Value{}, fmt.Errorf("cbor: TextMarshaler: %w", err)
				}
				return cbor.Text(string(data)), nil
			}
		}
	}

	switch rv.Kind() {
	case reflect.Bool:
		return cbor.Bool(rv.Bool()), nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := rv.Int()
		if n >= 0 {
			return cbor.Uint(uint64(n)), nil
		}
		return cbor.NegInt(uint64(-1 - n)), nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return cbor.Uint(rv.Uint()), nil

	case reflect.Float32:
		return cbor.Float32(float32(rv.Float())), nil

	case reflect.Float64:
		return cbor.Float64(rv.Float()), nil

	case reflect.String:
		return cbor.Text(rv.String()), nil

	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			if rv.IsNil() {
				return cbor.Null(), nil
			}
			return cbor.Bytes(rv.Bytes()), nil
		}
		if rv.IsNil() {
			return cbor.MakeArray(), nil
		}
		return sliceToValue(rv, opts)

	case reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			bs := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(bs), rv)
			return cbor.Bytes(bs), nil
		}
		return sliceToValue(rv, opts)

	case reflect.Map:
		if rv.IsNil() {
			return cbor.Null(), nil
		}
		return mapToValue(rv, opts)

	case reflect.Struct:
		return structToValue(rv, opts)

	case reflect.Interface:
		if rv.IsNil() {
			return cbor.Null(), nil
		}
		return reflectToValue(rv.Elem(), opts)

	default:
		return cbor.Value{}, fmt.Errorf("%w: %s", ErrUnsupportedType, rv.Type())
	}
}

// Decoders for Marshaler output. They have no internal arena, so they
// are safe for concurrent use and their Values outlive the call.
var (
	marshalerKeepDecoder   = NewDecoder(WithoutInternalArena(), KeepDuplicateMapKeys())
	marshalerRejectDecoder = NewDecoder(WithoutInternalArena(), RejectDuplicateMapKeys())
)

// marshalerToValue converts a Marshaler's output to a Value. Its bytes
// are always validated. In Permissive mode, RawMessage and RawTag bytes
// are spliced into the output verbatim, with no re-encoding; otherwise the output is decoded and
// re-encoded in the encoder's mode, which deterministic modes require.
//
// Repeated map keys in the output are never merged:
// the deterministic modes reject them with ErrDuplicateMapKey, as they
// do for any Value, and Permissive keeps every entry.
func marshalerToValue(m Marshaler, opts *marshalOpts) (cbor.Value, error) {
	data, err := m.MarshalCBOR()
	if err != nil {
		return cbor.Value{}, fmt.Errorf("cbor: Marshaler: %w", err)
	}
	dec := marshalerKeepDecoder
	if opts.Deterministic {
		dec = marshalerRejectDecoder
	}
	val, decErr := dec.Decode(data)
	if decErr != nil {
		return cbor.Value{}, fmt.Errorf("cbor: Marshaler produced invalid CBOR: %w", decErr)
	}
	if !opts.Deterministic {
		switch m.(type) {
		case RawMessage, *RawMessage, RawTag, *RawTag:
			return rawvalue.Make(data), nil
		}
	}
	return val, nil
}

func timeToValue(t time.Time) cbor.Value {
	if t.Nanosecond() != 0 {
		return cbor.TimeToFloat(t)
	}
	return cbor.TimeTo(t)
}

func sliceToValue(rv reflect.Value, opts *marshalOpts) (cbor.Value, error) {
	n := rv.Len()
	arr := make([]cbor.Value, n)
	for i := range n {
		val, err := reflectToValue(rv.Index(i), opts)
		if err != nil {
			return cbor.Value{}, err
		}
		arr[i] = val
	}
	return cbor.MakeArrayFromSlice(arr), nil
}

func mapToValue(rv reflect.Value, opts *marshalOpts) (cbor.Value, error) {
	entries := make([]cbor.MapEntry, 0, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		k, err := reflectToValue(iter.Key(), opts)
		if err != nil {
			return cbor.Value{}, err
		}
		v, err := reflectToValue(iter.Value(), opts)
		if err != nil {
			return cbor.Value{}, err
		}
		entries = append(entries, cbor.MapEntry{Key: k, Value: v})
	}
	return cbor.MakeMapFromSlice(entries), nil
}

func structToValue(rv reflect.Value, opts *marshalOpts) (cbor.Value, error) {
	sf := structFieldsFor(rv.Type(), opts.goNames)
	if sf.toArray {
		return structToArray(rv, sf, opts)
	}
	fields := sf.list
	entries := make([]cbor.MapEntry, 0, len(fields))

	for i := range fields {
		fi := &fields[i]
		fv, ok := fieldByIndex(rv, fi.index)
		if !ok {
			continue // nil embedded pointer: its fields are absent
		}
		if fi.omit && isZero(fv) {
			continue
		}
		if fi.omitZero && isZeroValue(fv) {
			continue
		}

		val, err := reflectToValue(fv, opts)
		if err != nil {
			return cbor.Value{}, err
		}

		if fi.hasTag {
			val = cbor.MakeTag(fi.tagID, val)
		}

		var key cbor.Value
		if fi.hasInt {
			if fi.intKey >= 0 {
				key = cbor.Uint(uint64(fi.intKey))
			} else {
				key = cbor.NegInt(uint64(-1 - fi.intKey))
			}
		} else {
			key = cbor.Text(fi.name)
		}

		entries = append(entries, cbor.MapEntry{Key: key, Value: val})
	}

	return cbor.MakeMapFromSlice(entries), nil
}

// structToArray encodes a toarray struct: its fields in declaration
// order, no keys. A field under a nil embedded pointer is null.
func structToArray(rv reflect.Value, sf *structFields, opts *marshalOpts) (cbor.Value, error) {
	if sf.arrayErr != nil {
		return cbor.Value{}, sf.arrayErr
	}
	items := make([]cbor.Value, len(sf.list))
	for i := range sf.list {
		fi := &sf.list[i]
		fv, ok := fieldByIndex(rv, fi.index)
		if !ok {
			items[i] = cbor.Null()
			continue
		}
		val, err := reflectToValue(fv, opts)
		if err != nil {
			return cbor.Value{}, err
		}
		if fi.hasTag {
			val = cbor.MakeTag(fi.tagID, val)
		}
		items[i] = val
	}
	return cbor.MakeArrayFromSlice(items), nil
}

type isZeroer interface{ IsZero() bool }

// isZeroValue is the omitzero test: an IsZero() bool method decides
// when the field's type (or a pointer to it) has one, otherwise
// reflect.Value.IsZero does, as in encoding/json.
func isZeroValue(rv reflect.Value) bool {
	if rv.Kind() == reflect.Pointer && rv.IsNil() {
		return true
	}
	if rv.CanInterface() {
		if z, ok := rv.Interface().(isZeroer); ok {
			return z.IsZero()
		}
		if rv.CanAddr() {
			if z, ok := rv.Addr().Interface().(isZeroer); ok {
				return z.IsZero()
			}
		}
	}
	return rv.IsZero()
}

func isZero(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.String:
		return rv.Len() == 0
	case reflect.Slice, reflect.Map:
		return rv.IsNil() || rv.Len() == 0
	case reflect.Pointer, reflect.Interface:
		return rv.IsNil()
	case reflect.Struct:
		if rv.Type() == timeType {
			return rv.Interface().(time.Time).IsZero()
		}
		return rv.IsZero()
	case reflect.Array:
		return rv.Len() == 0
	default:
		return false
	}
}

func intFromFloat(f float64) (int64, bool) {
	if f != math.Trunc(f) {
		return 0, false
	}
	if f >= math.MinInt64 && f <= math.MaxInt64 {
		return int64(f), true
	}
	return 0, false
}
