// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

// unmarshalState carries per-call reflection settings.
type unmarshalState struct {
	// clone is set when decoded Values may alias decoder-owned storage
	// (an arena) or the source buffer (zero-copy). Anything stored into
	// the caller's target as a cbor.Value is then deep-copied.
	clone bool
}

func unmarshalValue(val cbor.Value, v any, clone bool) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return ErrNotPointer
	}
	u := unmarshalState{clone: clone}
	return u.valueToGo(val, rv.Elem())
}

func (u unmarshalState) own(v cbor.Value) cbor.Value {
	if u.clone {
		return v.Clone()
	}
	return v
}

func (u unmarshalState) valueToGo(val cbor.Value, target reflect.Value) error {
	if !target.CanSet() {
		return fmt.Errorf("cbor: cannot set target of type %s", target.Type())
	}

	if target.Kind() == reflect.Pointer {
		if val.Kind == cbor.KindNull {
			target.SetZero()
			return nil
		}
		if target.IsNil() {
			target.Set(reflect.New(target.Type().Elem()))
		}
		return u.valueToGo(val, target.Elem())
	}

	if target.CanAddr() {
		if u, ok := target.Addr().Interface().(Unmarshaler); ok {
			return callUnmarshaler(u, val)
		}
	}

	if target.Type() == timeType {
		return decodeTime(val, target)
	}
	if target.Type() == bigIntType {
		return decodeBigInt(val, target)
	}
	if target.Type() == bigIntPtrType {
		return decodeBigIntPtr(val, target)
	}

	if target.Type() == valueType {
		target.Set(reflect.ValueOf(u.own(val)))
		return nil
	}

	if target.Kind() == reflect.Interface {
		goVal, err := u.valueToAny(val)
		if err != nil {
			return err
		}
		return setInterface(goVal, target)
	}

	switch val.Kind {
	case cbor.KindUint:
		return setUint(val.UintVal(), target)
	case cbor.KindNegInt:
		return setNegInt(val.NegIntVal(), target)
	case cbor.KindBool:
		if target.Kind() == reflect.Bool {
			target.SetBool(val.BoolVal())
			return nil
		}
		return typeMismatch("Bool", target.Type())
	case cbor.KindText:
		if target.Kind() == reflect.String {
			target.SetString(val.TextVal())
			return nil
		}
		return typeMismatch("Text", target.Type())
	case cbor.KindBytes:
		if target.Kind() == reflect.Slice && target.Type().Elem().Kind() == reflect.Uint8 {
			target.SetBytes(append([]byte(nil), val.BytesVal()...))
			return nil
		}
		return typeMismatch("Bytes", target.Type())
	case cbor.KindFloat32:
		return setFloat(float64(val.Float32Val()), target)
	case cbor.KindFloat64:
		return setFloat(val.Float64Val(), target)
	case cbor.KindArray:
		return u.decodeArray(val.Array(), target)
	case cbor.KindMap:
		return u.decodeMapReflect(val.Map(), target)
	case cbor.KindTag:
		return u.decodeTagReflect(val, target)
	case cbor.KindNull:
		target.SetZero()
		return nil
	case cbor.KindUndefined:
		target.SetZero()
		return nil
	default:
		return fmt.Errorf("cbor: unsupported Value kind %d for target %s", val.Kind, target.Type())
	}
}

// setInterface stores goVal in an interface-typed target, failing
// instead of panicking when goVal's type doesn't implement it.
func setInterface(goVal any, target reflect.Value) error {
	if goVal == nil {
		target.Set(reflect.Zero(target.Type()))
		return nil
	}
	rv := reflect.ValueOf(goVal)
	if !rv.Type().AssignableTo(target.Type()) {
		return typeMismatchf("cannot decode %s into Go type %s", rv.Type(), target.Type())
	}
	target.Set(rv)
	return nil
}

func callUnmarshaler(u Unmarshaler, val cbor.Value) error {
	enc := New(ModeCoreDeterministic)
	data, err := enc.Encode(nil, val)
	if err != nil {
		return fmt.Errorf("cbor: encoding for Unmarshaler: %w", err)
	}
	return u.UnmarshalCBOR(data)
}

func setUint(n uint64, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if target.OverflowUint(n) {
			return fmt.Errorf("%w: %d into %s", ErrOverflow, n, target.Type())
		}
		target.SetUint(n)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n > uint64(math.MaxInt64) {
			return fmt.Errorf("%w: %d into %s", ErrOverflow, n, target.Type())
		}
		i := int64(n)
		if target.OverflowInt(i) {
			return fmt.Errorf("%w: %d into %s", ErrOverflow, n, target.Type())
		}
		target.SetInt(i)
		return nil
	case reflect.Float32, reflect.Float64:
		target.SetFloat(float64(n))
		return nil
	case reflect.Interface:
		target.Set(reflect.ValueOf(n))
		return nil
	default:
		return typeMismatch("Uint", target.Type())
	}
}

func setNegInt(n uint64, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n > uint64(math.MaxInt64) {
			return fmt.Errorf("%w: negint(%d) into %s", ErrOverflow, n, target.Type())
		}
		i := -1 - int64(n)
		if target.OverflowInt(i) {
			return fmt.Errorf("%w: negint(%d) into %s", ErrOverflow, n, target.Type())
		}
		target.SetInt(i)
		return nil
	case reflect.Float32, reflect.Float64:
		target.SetFloat(-1 - float64(n))
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return fmt.Errorf("%w: negative integer into %s", ErrOverflow, target.Type())
	default:
		return typeMismatch("NegInt", target.Type())
	}
}

func setFloat(f float64, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Float32:
		if target.OverflowFloat(f) {
			return fmt.Errorf("%w: float %g into float32", ErrOverflow, f)
		}
		target.SetFloat(f)
		return nil
	case reflect.Float64:
		target.SetFloat(f)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, ok := intFromFloat(f)
		if !ok {
			return typeMismatch("Float", target.Type())
		}
		if target.OverflowInt(i) {
			return fmt.Errorf("%w: float %g into %s", ErrOverflow, f, target.Type())
		}
		target.SetInt(i)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if f < 0 || f != math.Trunc(f) {
			return typeMismatch("Float", target.Type())
		}
		u := uint64(f)
		if target.OverflowUint(u) {
			return fmt.Errorf("%w: float %g into %s", ErrOverflow, f, target.Type())
		}
		target.SetUint(u)
		return nil
	default:
		return typeMismatch("Float", target.Type())
	}
}

func (u unmarshalState) decodeArray(arr []cbor.Value, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Slice:
		if target.IsNil() || target.Cap() < len(arr) {
			target.Set(reflect.MakeSlice(target.Type(), len(arr), len(arr)))
		} else {
			target.SetLen(len(arr))
		}
		for i, elem := range arr {
			if err := u.valueToGo(elem, target.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Array:
		for i := range min(len(arr), target.Len()) {
			if err := u.valueToGo(arr[i], target.Index(i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return typeMismatch("Array", target.Type())
	}
}

func (u unmarshalState) decodeMapReflect(m []cbor.MapEntry, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Map:
		return u.decodeMapToMap(m, target)
	case reflect.Struct:
		return u.decodeMapToStruct(m, target)
	default:
		return typeMismatch("Map", target.Type())
	}
}

func (u unmarshalState) decodeMapToMap(m []cbor.MapEntry, target reflect.Value) error {
	if target.IsNil() {
		target.Set(reflect.MakeMapWithSize(target.Type(), len(m)))
	}
	keyType := target.Type().Key()
	valType := target.Type().Elem()

	for _, entry := range m {
		kv := reflect.New(keyType).Elem()
		if keyType.Kind() == reflect.Interface {
			// Interface-typed keys need a hashable dynamic value.
			k, err := u.keyToAny(entry.Key)
			if err != nil {
				return err
			}
			if err := setInterface(k, kv); err != nil {
				return err
			}
		} else if err := u.valueToGo(entry.Key, kv); err != nil {
			return err
		}
		if !kv.Comparable() {
			return typeMismatchf("map key of type %s is not comparable", kv.Type())
		}
		vv := reflect.New(valType).Elem()
		if err := u.valueToGo(entry.Value, vv); err != nil {
			return err
		}
		target.SetMapIndex(kv, vv)
	}
	return nil
}

func (u unmarshalState) decodeMapToStruct(m []cbor.MapEntry, target reflect.Value) error {
	fields := getStructFields(target.Type())

	for _, entry := range m {
		idx, found := -1, false

		switch entry.Key.Kind {
		case cbor.KindText:
			k := entry.Key.TextVal()
			idx, found = fields.byName[k]
			if !found {
				if n, err := strconv.ParseInt(k, 10, 64); err == nil {
					idx, found = fields.byInt[n]
				}
			}
		case cbor.KindUint:
			// Keys beyond int64 can't name an integer-keyed field; they
			// must not wrap around onto a negative one.
			if entry.Key.UintVal() <= math.MaxInt64 {
				idx, found = fields.byInt[int64(entry.Key.UintVal())]
			}
			if !found {
				idx, found = fields.byName[strconv.FormatUint(entry.Key.UintVal(), 10)]
			}
		case cbor.KindNegInt:
			if entry.Key.NegIntVal() <= math.MaxInt64 {
				idx, found = fields.byInt[-1-int64(entry.Key.NegIntVal())]
			}
		}

		if !found {
			continue
		}

		fi := &fields.list[idx]
		fv, err := fieldByIndexAlloc(target, fi.index)
		if err != nil {
			return err
		}
		val := entry.Value
		if fi.hasTag {
			if val.Kind != cbor.KindTag {
				return fmt.Errorf("cbor: field %q expects tag(%d) but got kind %d", fi.name, fi.tagID, val.Kind)
			}
			if val.TagID() != fi.tagID {
				return fmt.Errorf("cbor: field %q expects tag(%d) but got tag(%d)", fi.name, fi.tagID, val.TagID())
			}
			val = val.TagInner()
		}
		if err := u.valueToGo(val, fv); err != nil {
			return err
		}
	}
	return nil
}

func (u unmarshalState) decodeTagReflect(t cbor.Value, target reflect.Value) error {
	if target.Type() == timeType && (t.TagID() == cbor.TagEpochDateTime || t.TagID() == cbor.TagDateTimeString) {
		return decodeTime(t, target)
	}
	if target.Type() == bigIntType && (t.TagID() == cbor.TagUnsignedBignum || t.TagID() == cbor.TagNegativeBignum) {
		return decodeBigInt(t, target)
	}
	if target.Type() == bigIntPtrType && (t.TagID() == cbor.TagUnsignedBignum || t.TagID() == cbor.TagNegativeBignum) {
		return decodeBigIntPtr(t, target)
	}
	return u.valueToGo(t.TagInner(), target)
}

func decodeTime(val cbor.Value, target reflect.Value) error {
	if val.Kind != cbor.KindTag {
		return typeMismatch("non-Tag", timeType)
	}
	t, err := cbor.AsTime(val)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(t))
	return nil
}

func decodeBigInt(val cbor.Value, target reflect.Value) error {
	if val.Kind != cbor.KindTag {
		return typeMismatch("non-Tag", bigIntType)
	}
	bi, err := cbor.AsBigInt(val)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(*bi))
	return nil
}

func decodeBigIntPtr(val cbor.Value, target reflect.Value) error {
	if val.Kind != cbor.KindTag {
		return typeMismatch("non-Tag", bigIntPtrType)
	}
	bi, err := cbor.AsBigInt(val)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(bi))
	return nil
}

// valueToAny converts val to the Go value stored in an interface
// target. Negative integers below math.MinInt64 become *big.Int; tags
// stay cbor.Value.
func (u unmarshalState) valueToAny(val cbor.Value) (any, error) {
	switch val.Kind {
	case cbor.KindUint:
		return val.UintVal(), nil
	case cbor.KindNegInt:
		if val.NegIntVal() > math.MaxInt64 {
			n := new(big.Int).SetUint64(val.NegIntVal())
			return n.Neg(n.Add(n, big.NewInt(1))), nil
		}
		return -1 - int64(val.NegIntVal()), nil
	case cbor.KindBool:
		return val.BoolVal(), nil
	case cbor.KindText:
		return val.TextVal(), nil
	case cbor.KindBytes:
		b := val.BytesVal()
		cp := make([]byte, len(b))
		copy(cp, b)
		return cp, nil
	case cbor.KindFloat32:
		return float64(val.Float32Val()), nil
	case cbor.KindFloat64:
		return val.Float64Val(), nil
	case cbor.KindArray:
		items := val.Array()
		out := make([]any, len(items))
		for i, elem := range items {
			v, err := u.valueToAny(elem)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	case cbor.KindMap:
		pairs := val.Map()
		allText := true
		for _, entry := range pairs {
			if entry.Key.Kind != cbor.KindText {
				allText = false
				break
			}
		}
		if allText {
			out := make(map[string]any, len(pairs))
			for _, entry := range pairs {
				v, err := u.valueToAny(entry.Value)
				if err != nil {
					return nil, err
				}
				out[entry.Key.TextVal()] = v
			}
			return out, nil
		}
		out := make(map[any]any, len(pairs))
		for _, entry := range pairs {
			k, err := u.keyToAny(entry.Key)
			if err != nil {
				return nil, err
			}
			v, err := u.valueToAny(entry.Value)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case cbor.KindTag:
		return u.own(val), nil
	default:
		// Null, Undefined and unassigned simple values.
		return nil, nil
	}
}

// keyEncodeOpts is the Core Deterministic encoding used for EncodedKey.
var keyEncodeOpts = rfc8949.EncodeOpts{
	Deterministic:        true,
	SortMode:             rfc8949.SortBytewiseLex,
	FloatMode:            rfc8949.FloatShortest,
	AllowNonFiniteFloats: true,
	AllowInvalidUTF8:     true,
}

// keyToAny converts a non-text map key to a value usable as a Go map
// key. Kinds whose natural Go form isn't hashable (byte strings,
// containers, tags) and negative integers below math.MinInt64 map to
// cbor.ByteKey or cbor.EncodedKey; every other kind converts exactly as
// valueToAny does.
func (u unmarshalState) keyToAny(k cbor.Value) (any, error) {
	switch k.Kind {
	case cbor.KindBytes:
		return cbor.ByteKey(k.BytesVal()), nil
	case cbor.KindArray, cbor.KindMap, cbor.KindTag:
	case cbor.KindNegInt:
		if k.NegIntVal() <= math.MaxInt64 {
			return u.valueToAny(k)
		}
	default:
		return u.valueToAny(k)
	}
	enc, err := rfc8949.Encode(nil, k, keyEncodeOpts)
	if err != nil {
		return nil, fmt.Errorf("cbor: encoding map key for map[any]any: %w", err)
	}
	return cbor.EncodedKey(enc), nil
}

func typeMismatch(cborType string, goType reflect.Type) error {
	return fmt.Errorf("cbor: cannot decode %s into Go type %s", cborType, goType)
}

func typeMismatchf(format string, args ...any) error {
	return fmt.Errorf("cbor: "+format, args...)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
