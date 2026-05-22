// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"fmt"
	"math"
	"reflect"
	"strconv"

	"github.com/jahkeup/corecbor/cbor"
)

func unmarshalValue(val cbor.Value, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return ErrNotPointer
	}
	return valueToGo(val, rv.Elem())
}

func valueToGo(val cbor.Value, target reflect.Value) error {
	if !target.CanSet() {
		return fmt.Errorf("cbor: cannot set target of type %s", target.Type())
	}

	if target.Kind() == reflect.Pointer {
		if val.Kind() == cbor.KindNull {
			target.SetZero()
			return nil
		}
		if target.IsNil() {
			target.Set(reflect.New(target.Type().Elem()))
		}
		return valueToGo(val, target.Elem())
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
		target.Set(reflect.ValueOf(val))
		return nil
	}

	if target.Kind() == reflect.Interface {
		goVal := valueToAny(val)
		if goVal == nil {
			target.Set(reflect.Zero(target.Type()))
		} else {
			target.Set(reflect.ValueOf(goVal))
		}
		return nil
	}

	switch val.Kind() {
	case cbor.KindUint:
		return setUint(val.Uint(), target)
	case cbor.KindNegInt:
		return setNegInt(val.NegInt(), target)
	case cbor.KindBool:
		if target.Kind() == reflect.Bool {
			target.SetBool(val.Bool())
			return nil
		}
		return typeMismatch("Bool", target.Type())
	case cbor.KindText:
		if target.Kind() == reflect.String {
			target.SetString(val.Text())
			return nil
		}
		return typeMismatch("Text", target.Type())
	case cbor.KindBytes:
		if target.Kind() == reflect.Slice && target.Type().Elem().Kind() == reflect.Uint8 {
			b := val.Bytes()
			target.SetBytes(append([]byte(nil), b...))
			return nil
		}
		return typeMismatch("Bytes", target.Type())
	case cbor.KindFloat32:
		return setFloat(float64(val.Float32()), target)
	case cbor.KindFloat64:
		return setFloat(val.Float64(), target)
	case cbor.KindArray:
		return decodeArray(val.Array(), target)
	case cbor.KindMap:
		return decodeMap(val.Map(), target)
	case cbor.KindTag:
		return decodeTag(val, target)
	case cbor.KindNull:
		target.SetZero()
		return nil
	case cbor.KindUndefined:
		target.SetZero()
		return nil
	default:
		return fmt.Errorf("cbor: unsupported Value kind %d for target %s", val.Kind(), target.Type())
	}
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

func decodeArray(arr []cbor.Value, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Slice:
		if target.IsNil() || target.Cap() < len(arr) {
			target.Set(reflect.MakeSlice(target.Type(), len(arr), len(arr)))
		} else {
			target.SetLen(len(arr))
		}
		for i, elem := range arr {
			if err := valueToGo(elem, target.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Array:
		for i := range min(len(arr), target.Len()) {
			if err := valueToGo(arr[i], target.Index(i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return typeMismatch("Array", target.Type())
	}
}

func decodeMap(m []cbor.MapEntry, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Map:
		return decodeMapToMap(m, target)
	case reflect.Struct:
		return decodeMapToStruct(m, target)
	default:
		return typeMismatch("Map", target.Type())
	}
}

func decodeMapToMap(m []cbor.MapEntry, target reflect.Value) error {
	if target.IsNil() {
		target.Set(reflect.MakeMapWithSize(target.Type(), len(m)))
	}
	keyType := target.Type().Key()
	valType := target.Type().Elem()

	for _, entry := range m {
		kv := reflect.New(keyType).Elem()
		if err := valueToGo(entry.Key, kv); err != nil {
			return err
		}
		vv := reflect.New(valType).Elem()
		if err := valueToGo(entry.Value, vv); err != nil {
			return err
		}
		target.SetMapIndex(kv, vv)
	}
	return nil
}

func decodeMapToStruct(m []cbor.MapEntry, target reflect.Value) error {
	fields := getStructFields(target.Type())
	fieldMap := make(map[string]fieldInfo, len(fields))
	intKeyMap := make(map[int64]fieldInfo)
	for _, fi := range fields {
		if fi.hasInt {
			intKeyMap[fi.intKey] = fi
		} else {
			fieldMap[fi.name] = fi
		}
	}

	for _, entry := range m {
		var fi fieldInfo
		var found bool

		switch entry.Key.Kind() {
		case cbor.KindText:
			k := entry.Key.Text()
			fi, found = fieldMap[k]
			if !found {
				if n, err := strconv.ParseInt(k, 10, 64); err == nil {
					fi, found = intKeyMap[n]
				}
			}
		case cbor.KindUint:
			fi, found = intKeyMap[int64(entry.Key.Uint())]
			if !found {
				fi, found = fieldMap[strconv.FormatUint(entry.Key.Uint(), 10)]
			}
		case cbor.KindNegInt:
			neg := -1 - int64(entry.Key.NegInt())
			fi, found = intKeyMap[neg]
		}

		if !found {
			continue
		}

		fv := target.Field(fi.index)
		val := entry.Value
		if fi.hasTag {
			if val.Kind() != cbor.KindTag {
				return fmt.Errorf("cbor: field %q expects tag(%d) but got kind %d", fi.name, fi.tagID, val.Kind())
			}
			if val.TagID() != fi.tagID {
				return fmt.Errorf("cbor: field %q expects tag(%d) but got tag(%d)", fi.name, fi.tagID, val.TagID())
			}
			val = val.TagInner()
		}
		if err := valueToGo(val, fv); err != nil {
			return err
		}
	}
	return nil
}

func decodeTag(t cbor.Value, target reflect.Value) error {
	if target.Type() == timeType && (t.TagID() == cbor.TagEpochDateTime || t.TagID() == cbor.TagDateTimeString) {
		return decodeTime(t, target)
	}
	if target.Type() == bigIntType && (t.TagID() == cbor.TagUnsignedBignum || t.TagID() == cbor.TagNegativeBignum) {
		return decodeBigInt(t, target)
	}
	if target.Type() == bigIntPtrType && (t.TagID() == cbor.TagUnsignedBignum || t.TagID() == cbor.TagNegativeBignum) {
		return decodeBigIntPtr(t, target)
	}
	return valueToGo(t.TagInner(), target)
}

func decodeTime(val cbor.Value, target reflect.Value) error {
	if val.Kind() != cbor.KindTag {
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
	if val.Kind() != cbor.KindTag {
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
	if val.Kind() != cbor.KindTag {
		return typeMismatch("non-Tag", bigIntPtrType)
	}
	bi, err := cbor.AsBigInt(val)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(bi))
	return nil
}

func valueToAny(val cbor.Value) any {
	switch val.Kind() {
	case cbor.KindUint:
		return uint64(val.Uint())
	case cbor.KindNegInt:
		return -1 - int64(val.NegInt())
	case cbor.KindBool:
		return val.Bool()
	case cbor.KindText:
		return val.Text()
	case cbor.KindBytes:
		b := val.Bytes()
		cp := make([]byte, len(b))
		copy(cp, b)
		return cp
	case cbor.KindFloat32:
		return float64(val.Float32())
	case cbor.KindFloat64:
		return val.Float64()
	case cbor.KindArray:
		arr := val.Array()
		out := make([]any, len(arr))
		for i, elem := range arr {
			out[i] = valueToAny(elem)
		}
		return out
	case cbor.KindMap:
		m := val.Map()
		allText := true
		for _, entry := range m {
			if entry.Key.Kind() != cbor.KindText {
				allText = false
				break
			}
		}
		if allText {
			out := make(map[string]any, len(m))
			for _, entry := range m {
				out[entry.Key.Text()] = valueToAny(entry.Value)
			}
			return out
		}
		out := make(map[any]any, len(m))
		for _, entry := range m {
			out[valueToAny(entry.Key)] = valueToAny(entry.Value)
		}
		return out
	case cbor.KindTag:
		return val
	case cbor.KindNull:
		return nil
	case cbor.KindUndefined:
		return nil
	default:
		return val
	}
}

func typeMismatch(cborType string, goType reflect.Type) error {
	return fmt.Errorf("cbor: cannot decode %s into Go type %s", cborType, goType)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
