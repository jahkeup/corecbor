// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

var (
	valueType     = reflect.TypeFor[cbor.Value]()
	timeType      = reflect.TypeFor[time.Time]()
	bigIntType    = reflect.TypeFor[big.Int]()
	bigIntPtrType = reflect.TypeFor[*big.Int]()
)

func goToValue(v any, opts rfc8949.EncodeOpts) (cbor.Value, error) {
	if v == nil {
		return cbor.Null(), nil
	}
	if val, ok := v.(cbor.Value); ok {
		return val, nil
	}
	return reflectToValue(reflect.ValueOf(v), opts)
}

func reflectToValue(rv reflect.Value, opts rfc8949.EncodeOpts) (cbor.Value, error) {
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
			return marshalerToValue(m)
		}
		if rv.CanAddr() {
			if m, ok := rv.Addr().Interface().(Marshaler); ok {
				return marshalerToValue(m)
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

func marshalerToValue(m Marshaler) (cbor.Value, error) {
	data, err := m.MarshalCBOR()
	if err != nil {
		return cbor.Value{}, fmt.Errorf("cbor: Marshaler: %w", err)
	}
	dec := NewDecoder()
	val, decErr := dec.Decode(data)
	if decErr != nil {
		return cbor.Value{}, fmt.Errorf("cbor: Marshaler produced invalid CBOR: %w", decErr)
	}
	return val, nil
}

func timeToValue(t time.Time) cbor.Value {
	if t.Nanosecond() != 0 {
		return cbor.TimeToFloat(t)
	}
	sec := t.Unix()
	if sec >= 0 {
		return cbor.MakeTag(cbor.TagEpochDateTime, cbor.Uint(uint64(sec)))
	}
	return cbor.MakeTag(cbor.TagEpochDateTime, cbor.NegInt(uint64(-1-sec)))
}

func sliceToValue(rv reflect.Value, opts rfc8949.EncodeOpts) (cbor.Value, error) {
	n := rv.Len()
	arr := make([]cbor.Value, n)
	for i := range n {
		val, err := reflectToValue(rv.Index(i), opts)
		if err != nil {
			return cbor.Value{}, err
		}
		arr[i] = val
	}
	return cbor.MakeArray(arr...), nil
}

func mapToValue(rv reflect.Value, opts rfc8949.EncodeOpts) (cbor.Value, error) {
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
	return cbor.MakeMap(entries...), nil
}

type fieldInfo struct {
	index  int
	name   string
	intKey int64
	hasInt bool
	omit   bool
	tagID  uint64
	hasTag bool
}

func structToValue(rv reflect.Value, opts rfc8949.EncodeOpts) (cbor.Value, error) {
	rt := rv.Type()
	fields := getStructFields(rt)
	entries := make([]cbor.MapEntry, 0, len(fields))

	for _, fi := range fields {
		fv := rv.Field(fi.index)
		if fi.omit && isZero(fv) {
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

	return cbor.MakeMap(entries...), nil
}

func getStructFields(rt reflect.Type) []fieldInfo {
	var fields []fieldInfo
	for i := range rt.NumField() {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		if f.Anonymous {
			if f.Type.Kind() == reflect.Struct {
				embedded := getStructFields(f.Type)
				for _, ef := range embedded {
					ef.index = i
					fields = append(fields, ef)
				}
			}
			continue
		}

		tag := f.Tag.Get("cbor")
		if tag == "-" {
			continue
		}

		fi := fieldInfo{index: i}
		if tag == "" {
			fi.name = strings.ToLower(f.Name)
		} else {
			parts := strings.Split(tag, ",")
			fi.name = parts[0]
			for _, opt := range parts[1:] {
				if opt == "omitempty" {
					fi.omit = true
				} else if strings.HasPrefix(opt, "tag=") {
					if n, err := strconv.ParseUint(opt[4:], 10, 64); err == nil {
						fi.tagID = n
						fi.hasTag = true
					}
				}
			}
			if n, err := strconv.ParseInt(fi.name, 10, 64); err == nil {
				fi.intKey = n
				fi.hasInt = true
			}
		}
		fields = append(fields, fi)
	}
	return fields
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

// intFromFloat safely converts a float64 to int64 if it has no fractional part.
func intFromFloat(f float64) (int64, bool) {
	if f != math.Trunc(f) {
		return 0, false
	}
	if f >= math.MinInt64 && f <= math.MaxInt64 {
		return int64(f), true
	}
	return 0, false
}
