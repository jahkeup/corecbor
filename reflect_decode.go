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
		if _, ok := val.(cbor.Null); ok {
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

	if target.Type().Implements(valueType) || reflect.PointerTo(target.Type()).Implements(valueType) {
		if target.Type().AssignableTo(reflect.TypeOf(val)) {
			target.Set(reflect.ValueOf(val))
			return nil
		}
	}

	if target.Kind() == reflect.Interface {
		goVal := valueToAny(val)
		target.Set(reflect.ValueOf(goVal))
		return nil
	}

	switch v := val.(type) {
	case cbor.Uint:
		return setUint(uint64(v), target)
	case cbor.NegInt:
		return setNegInt(uint64(v), target)
	case cbor.Bool:
		if target.Kind() == reflect.Bool {
			target.SetBool(bool(v))
			return nil
		}
		return typeMismatch("Bool", target.Type())
	case cbor.Text:
		if target.Kind() == reflect.String {
			target.SetString(string(v))
			return nil
		}
		return typeMismatch("Text", target.Type())
	case cbor.Bytes:
		if target.Kind() == reflect.Slice && target.Type().Elem().Kind() == reflect.Uint8 {
			target.SetBytes(append([]byte(nil), v...))
			return nil
		}
		return typeMismatch("Bytes", target.Type())
	case cbor.Float32:
		return setFloat(float64(v), target)
	case cbor.Float64:
		return setFloat(float64(v), target)
	case cbor.Array:
		return decodeArray(v, target)
	case cbor.Map:
		return decodeMap(v, target)
	case cbor.Tag:
		return decodeTag(v, target)
	case cbor.Null:
		target.SetZero()
		return nil
	case cbor.Undefined:
		target.SetZero()
		return nil
	default:
		return fmt.Errorf("cbor: unsupported Value type %T for target %s", val, target.Type())
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

func decodeArray(arr cbor.Array, target reflect.Value) error {
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

func decodeMap(m cbor.Map, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Map:
		return decodeMapToMap(m, target)
	case reflect.Struct:
		return decodeMapToStruct(m, target)
	default:
		return typeMismatch("Map", target.Type())
	}
}

func decodeMapToMap(m cbor.Map, target reflect.Value) error {
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

func decodeMapToStruct(m cbor.Map, target reflect.Value) error {
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

		switch k := entry.Key.(type) {
		case cbor.Text:
			fi, found = fieldMap[string(k)]
			if !found {
				if n, err := strconv.ParseInt(string(k), 10, 64); err == nil {
					fi, found = intKeyMap[n]
				}
			}
		case cbor.Uint:
			fi, found = intKeyMap[int64(k)]
			if !found {
				fi, found = fieldMap[strconv.FormatUint(uint64(k), 10)]
			}
		case cbor.NegInt:
			neg := -1 - int64(k)
			fi, found = intKeyMap[neg]
		}

		if !found {
			continue
		}

		fv := target.Field(fi.index)
		if err := valueToGo(entry.Value, fv); err != nil {
			return err
		}
	}
	return nil
}

func decodeTag(t cbor.Tag, target reflect.Value) error {
	if target.Type() == timeType && (t.ID == cbor.TagEpochDateTime || t.ID == cbor.TagDateTimeString) {
		return decodeTime(t, target)
	}
	if target.Type() == bigIntType && (t.ID == cbor.TagUnsignedBignum || t.ID == cbor.TagNegativeBignum) {
		return decodeBigInt(t, target)
	}
	if target.Type() == bigIntPtrType && (t.ID == cbor.TagUnsignedBignum || t.ID == cbor.TagNegativeBignum) {
		return decodeBigIntPtr(t, target)
	}
	return valueToGo(t.Inner, target)
}

func decodeTime(val cbor.Value, target reflect.Value) error {
	tag, ok := val.(cbor.Tag)
	if !ok {
		return typeMismatch("non-Tag", timeType)
	}
	t, err := cbor.AsTime(tag)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(t))
	return nil
}

func decodeBigInt(val cbor.Value, target reflect.Value) error {
	tag, ok := val.(cbor.Tag)
	if !ok {
		return typeMismatch("non-Tag", bigIntType)
	}
	bi, err := cbor.AsBigInt(tag)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(*bi))
	return nil
}

func decodeBigIntPtr(val cbor.Value, target reflect.Value) error {
	tag, ok := val.(cbor.Tag)
	if !ok {
		return typeMismatch("non-Tag", bigIntPtrType)
	}
	bi, err := cbor.AsBigInt(tag)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(bi))
	return nil
}

func valueToAny(val cbor.Value) any {
	switch v := val.(type) {
	case cbor.Uint:
		return uint64(v)
	case cbor.NegInt:
		return -1 - int64(v)
	case cbor.Bool:
		return bool(v)
	case cbor.Text:
		return string(v)
	case cbor.Bytes:
		cp := make([]byte, len(v))
		copy(cp, v)
		return cp
	case cbor.Float32:
		return float64(v)
	case cbor.Float64:
		return float64(v)
	case cbor.Array:
		out := make([]any, len(v))
		for i, elem := range v {
			out[i] = valueToAny(elem)
		}
		return out
	case cbor.Map:
		allText := true
		for _, entry := range v {
			if _, ok := entry.Key.(cbor.Text); !ok {
				allText = false
				break
			}
		}
		if allText {
			out := make(map[string]any, len(v))
			for _, entry := range v {
				out[string(entry.Key.(cbor.Text))] = valueToAny(entry.Value)
			}
			return out
		}
		out := make(map[any]any, len(v))
		for _, entry := range v {
			out[valueToAny(entry.Key)] = valueToAny(entry.Value)
		}
		return out
	case cbor.Tag:
		return v
	case cbor.Null:
		return nil
	case cbor.Undefined:
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
