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

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

// unmarshalState carries per-call reflection settings.
type unmarshalState struct {
	// clone is set when decoded Values may alias decoder-owned storage
	// (an arena) or the source buffer (zero-copy). Anything stored into
	// the caller's target as a cbor.Value is then deep-copied.
	clone bool
	// lossless lets string targets take byte strings (and tags
	// 272/273/274 around them) with their exact bytes
	// (InvalidUTF8Lossless, proposal 035).
	lossless bool

	// Proposal 025.
	disallowUnknown    bool // DisallowUnknownFields
	caseInsensitive    bool // WithCaseInsensitiveFieldNames
	legacyNoTextBinary bool // WithLegacyNoTextBinaryUnmarshal
}

func unmarshalValue(val cbor.Value, v any, u unmarshalState) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return ErrNotPointer
	}
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
		return unsupportedTarget(cbor.KindInvalid, target.Type(), "cannot set target of type %s", target.Type())
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

	// encoding.BinaryUnmarshaler takes byte strings and
	// encoding.TextUnmarshaler text strings, mirroring encode (proposal
	// 025; 008 documents both as supported).
	if !u.legacyNoTextBinary && (val.Kind == cbor.KindText || val.Kind == cbor.KindBytes) &&
		target.CanAddr() && mayHaveMethods(target.Type()) {
		if done, err := callTextBinary(val, target); done {
			return err
		}
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
		return typeMismatch(cbor.KindBool, "Bool", target.Type())
	case cbor.KindText:
		if target.Kind() == reflect.String {
			target.SetString(val.TextVal())
			return nil
		}
		return typeMismatch(cbor.KindText, "Text", target.Type())
	case cbor.KindBytes:
		if target.Kind() == reflect.Slice && target.Type().Elem().Kind() == reflect.Uint8 {
			target.SetBytes(append([]byte(nil), val.BytesVal()...))
			return nil
		}
		if u.lossless && target.Kind() == reflect.String {
			target.SetString(string(val.BytesVal()))
			return nil
		}
		return typeMismatch(cbor.KindBytes, "Bytes", target.Type())
	case cbor.KindFloat32:
		return setFloat(float64(val.Float32Val()), cbor.KindFloat32, target)
	case cbor.KindFloat64:
		return setFloat(val.Float64Val(), cbor.KindFloat64, target)
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
		return typeMismatchf(val.Kind, target.Type(), "unsupported Value kind %d for target %s", val.Kind, target.Type())
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
		return typeMismatchf(cbor.KindInvalid, target.Type(), "cannot decode %s into Go type %s", rv.Type(), target.Type())
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
			return overflowErr(cbor.KindUint, target.Type(), "%d into %s", n, target.Type())
		}
		target.SetUint(n)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n > uint64(math.MaxInt64) {
			return overflowErr(cbor.KindUint, target.Type(), "%d into %s", n, target.Type())
		}
		i := int64(n)
		if target.OverflowInt(i) {
			return overflowErr(cbor.KindUint, target.Type(), "%d into %s", n, target.Type())
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
		return typeMismatch(cbor.KindUint, "Uint", target.Type())
	}
}

func setNegInt(n uint64, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n > uint64(math.MaxInt64) {
			return overflowErr(cbor.KindNegInt, target.Type(), "negint(%d) into %s", n, target.Type())
		}
		i := -1 - int64(n)
		if target.OverflowInt(i) {
			return overflowErr(cbor.KindNegInt, target.Type(), "negint(%d) into %s", n, target.Type())
		}
		target.SetInt(i)
		return nil
	case reflect.Float32, reflect.Float64:
		target.SetFloat(-1 - float64(n))
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return overflowErr(cbor.KindNegInt, target.Type(), "negative integer into %s", target.Type())
	default:
		return typeMismatch(cbor.KindNegInt, "NegInt", target.Type())
	}
}

func setFloat(f float64, kind cbor.Kind, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Float32:
		if target.OverflowFloat(f) {
			// A float overflow, not an integer one: keep ErrOverflow but
			// not its "integer overflow" text (037 C22).
			return &UnmarshalTypeError{
				CBORKind: kind, GoType: target.Type(), Err: ErrOverflow,
				msg: fmt.Sprintf("cbor: float %g overflows %s", f, target.Type()),
			}
		}
		target.SetFloat(f)
		return nil
	case reflect.Float64:
		target.SetFloat(f)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, ok := intFromFloat(f)
		if !ok {
			return typeMismatch(kind, "Float", target.Type())
		}
		if target.OverflowInt(i) {
			return overflowErr(kind, target.Type(), "float %g into %s", f, target.Type())
		}
		target.SetInt(i)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if f < 0 || f != math.Trunc(f) {
			return typeMismatch(kind, "Float", target.Type())
		}
		u := uint64(f)
		if target.OverflowUint(u) {
			return overflowErr(kind, target.Type(), "float %g into %s", f, target.Type())
		}
		target.SetUint(u)
		return nil
	default:
		return typeMismatch(kind, "Float", target.Type())
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
		return u.decodeElems(arr, target, len(arr))
	case reflect.Array:
		return u.decodeElems(arr, target, min(len(arr), target.Len()))
	case reflect.Struct:
		sf := getStructFields(target.Type())
		if !sf.toArray {
			return typeMismatch(cbor.KindArray, "Array", target.Type())
		}
		if err := checkArrayLen(sf, len(arr), target.Type()); err != nil {
			return err
		}
		for i := range arr {
			fi := &sf.list[i]
			fv, err := fieldByIndexAlloc(target, fi.index)
			if err != nil {
				return err
			}
			val, err := untagField(fi, arr[i], fv.Type())
			if err != nil {
				return err
			}
			if err := u.valueToGo(val, fv); err != nil {
				return withField(err, fi.goName)
			}
		}
		return nil
	default:
		return typeMismatch(cbor.KindArray, "Array", target.Type())
	}
}

// checkArrayLen validates an array of n items against toarray struct
// fields sf: no more items than fields, and missing trailing fields
// must be pointers (CDDL "? optional" tail items).
func checkArrayLen(sf *structFields, n int, t reflect.Type) error {
	if sf.arrayErr != nil {
		return sf.arrayErr
	}
	if n > len(sf.list) {
		return fmt.Errorf("%w: %s has %d fields, array has %d items", ErrArrayLength, t, len(sf.list), n)
	}
	for i := n; i < len(sf.list); i++ {
		if ft := t.FieldByIndex(sf.list[i].index).Type; ft.Kind() != reflect.Pointer {
			return fmt.Errorf("%w: %s has %d fields, array has %d items and field %s isn't optional (a pointer)",
				ErrArrayLength, t, len(sf.list), n, sf.list[i].goName)
		}
	}
	return nil
}

// untagField strips a field's declared tag=N wrapper from val.
func untagField(fi *fieldInfo, val cbor.Value, ft reflect.Type) (cbor.Value, error) {
	if !fi.hasTag {
		return val, nil
	}
	if val.Kind != cbor.KindTag {
		return val, withField(typeMismatchf(val.Kind, ft, "field %q expects tag(%d) but got kind %d", fi.name, fi.tagID, val.Kind), fi.goName)
	}
	if val.TagID() != fi.tagID {
		return val, withField(typeMismatchf(val.Kind, ft, "field %q expects tag(%d) but got tag(%d)", fi.name, fi.tagID, val.TagID()), fi.goName)
	}
	return val.TagInner(), nil
}

// mayHaveMethods reports whether t (or *t) can have methods: named
// types and structs (which can promote methods from embedded fields).
// Predeclared and other unnamed types such as string or []byte can't,
// so the interface checks are skipped for them.
// decodeElems decodes arr[:n] into the first n elements of a slice or
// array target. For built-in scalar element types (see plainScalar) the
// common kinds are set directly, skipping valueToGo's per-element
// Unmarshaler and special-type checks, which can't apply; the setters
// are the ones valueToGo calls, so results and errors are identical.
// Every other kind, and every other element type, goes through
// valueToGo.
func (u unmarshalState) decodeElems(arr []cbor.Value, target reflect.Value, n int) error {
	if !plainScalar(target.Type().Elem()) {
		for i := range n {
			if err := u.valueToGo(arr[i], target.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}
	if target.Kind() == reflect.Slice && u.decodeTypedSlice(arr[:n], target) {
		return nil
	}
	for i := range n {
		elem := &arr[i]
		ev := target.Index(i)
		var err error
		switch {
		case elem.Kind == cbor.KindUint:
			err = setUint(elem.Num, ev)
		case elem.Kind == cbor.KindNegInt:
			err = setNegInt(elem.Num, ev)
		case elem.Kind == cbor.KindFloat64:
			err = setFloat(elem.Float64Val(), cbor.KindFloat64, ev)
		case elem.Kind == cbor.KindFloat32:
			err = setFloat(float64(elem.Float32Val()), cbor.KindFloat32, ev)
		case elem.Kind == cbor.KindBool && ev.Kind() == reflect.Bool:
			ev.SetBool(elem.Num != 0)
		case elem.Kind == cbor.KindText && ev.Kind() == reflect.String:
			ev.SetString(elem.Str)
		default:
			err = u.valueToGo(*elem, ev)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// decodeTypedSlice fills the most common unnamed scalar slices without
// per-element reflection when every element is of the one CBOR kind
// that maps to the element type without conversion or range checks. It
// reports false, having written nothing observable beyond elements the
// generic path would also write, when any element needs the generic
// path; the caller then decodes every element generically.
func (u unmarshalState) decodeTypedSlice(arr []cbor.Value, target reflect.Value) bool {
	if !target.CanAddr() {
		return false
	}
	// A pointer in an interface doesn't allocate; the slice header would.
	switch p := target.Addr().Interface().(type) {
	case *[]uint64:
		s := *p
		for i := range arr {
			if arr[i].Kind != cbor.KindUint {
				return false
			}
			s[i] = arr[i].Num
		}
		return true
	case *[]string:
		s := *p
		for i := range arr {
			if arr[i].Kind != cbor.KindText {
				return false
			}
			s[i] = arr[i].Str
		}
		return true
	case *[]float64:
		s := *p
		for i := range arr {
			if arr[i].Kind != cbor.KindFloat64 {
				return false
			}
			s[i] = arr[i].Float64Val()
		}
		return true
	case *[]bool:
		s := *p
		for i := range arr {
			if arr[i].Kind != cbor.KindBool {
				return false
			}
			s[i] = arr[i].Num != 0
		}
		return true
	}
	return false
}

// plainScalar reports whether t is a predeclared bool, integer, float or
// string type. Such a type has no methods (so no Unmarshaler,
// TextUnmarshaler or BinaryUnmarshaler) and is none of the special
// targets (time.Time, big.Int, cbor.Value, interfaces, pointers).
func plainScalar(t reflect.Type) bool {
	if t.PkgPath() != "" {
		return false
	}
	switch t.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

func mayHaveMethods(t reflect.Type) bool {
	if t == stringType || t == bytesType { // the common targets, compared by identity
		return false
	}
	return t.PkgPath() != "" || t.Kind() == reflect.Struct
}

var (
	stringType = reflect.TypeFor[string]()
	bytesType  = reflect.TypeFor[[]byte]()
)

// callTextBinary calls target's encoding.BinaryUnmarshaler for a byte
// string or encoding.TextUnmarshaler for a text string. done is false
// when neither applies.
func callTextBinary(val cbor.Value, target reflect.Value) (done bool, err error) {
	switch val.Kind {
	case cbor.KindBytes:
		if m, ok := target.Addr().Interface().(encoding.BinaryUnmarshaler); ok {
			if err := m.UnmarshalBinary(append([]byte(nil), val.Bstr...)); err != nil {
				return true, fmt.Errorf("cbor: UnmarshalBinary into %s: %w", target.Type(), err)
			}
			return true, nil
		}
	case cbor.KindText:
		if m, ok := target.Addr().Interface().(encoding.TextUnmarshaler); ok {
			if err := m.UnmarshalText([]byte(val.Str)); err != nil {
				return true, fmt.Errorf("cbor: UnmarshalText into %s: %w", target.Type(), err)
			}
			return true, nil
		}
	}
	return false, nil
}

// unknownField reports a map key that names no struct field.
func unknownField(key cbor.Value, t reflect.Type) error {
	return fmt.Errorf("%w: %s has no field for key %s", ErrUnknownField, t, key)
}

// fieldFor resolves a map key to a field index under u's matching
// rules. exact (from structFields.exactFields) is non-nil only for
// case-insensitive matching. ok is false for keys to skip; err is set
// for keys DisallowUnknownFields rejects.
func (u unmarshalState) fieldFor(sf *structFields, key cbor.Value, exact []bool, t reflect.Type) (idx int, ok bool, err error) {
	if !u.caseInsensitive {
		if idx, ok := sf.lookup(key); ok {
			return idx, true, nil
		}
	} else if idx, isExact, ok := sf.lookupFold(key); ok && (isExact || !exact[idx]) {
		return idx, true, nil
	}
	if u.disallowUnknown {
		return -1, false, unknownField(key, t)
	}
	return -1, false, nil
}

func (u unmarshalState) decodeMapReflect(m []cbor.MapEntry, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Map:
		return u.decodeMapToMap(m, target)
	case reflect.Struct:
		return u.decodeMapToStruct(m, target)
	default:
		return typeMismatch(cbor.KindMap, "Map", target.Type())
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
			return typeMismatchf(entry.Key.Kind, kv.Type(), "map key of type %s is not comparable", kv.Type())
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
	if fields.toArray {
		return typeMismatch(cbor.KindMap, "Map", target.Type())
	}
	var exact []bool
	if u.caseInsensitive {
		exact = fields.exactFields(func(yield func(cbor.Value) bool) {
			for i := range m {
				if !yield(m[i].Key) {
					return
				}
			}
		})
	}

	for _, entry := range m {
		// An exact match wins under every option, so only a miss needs
		// fieldFor's case-insensitive / unknown-field handling.
		idx, found := fields.lookup(entry.Key)
		if !found && (u.caseInsensitive || u.disallowUnknown) {
			var err error
			if idx, found, err = u.fieldFor(fields, entry.Key, exact, target.Type()); err != nil {
				return err
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
				return withField(typeMismatchf(val.Kind, fv.Type(), "field %q expects tag(%d) but got kind %d", fi.name, fi.tagID, val.Kind), fi.goName)
			}
			if val.TagID() != fi.tagID {
				return withField(typeMismatchf(val.Kind, fv.Type(), "field %q expects tag(%d) but got tag(%d)", fi.name, fi.tagID, val.TagID()), fi.goName)
			}
			val = val.TagInner()
		}
		if err := u.valueToGo(val, fv); err != nil {
			return withField(err, fi.goName)
		}
	}
	return nil
}

// lookup returns the index in f.list of the field a map key names.
func (f *structFields) lookup(key cbor.Value) (int, bool) {
	switch key.Kind {
	case cbor.KindText:
		k := key.TextVal()
		if idx, ok := f.byName[k]; ok {
			return idx, true
		}
		if n, err := strconv.ParseInt(k, 10, 64); err == nil {
			idx, ok := f.byInt[n]
			return idx, ok
		}
	case cbor.KindUint:
		// Keys beyond int64 can't name an integer-keyed field; they
		// must not wrap around onto a negative one.
		if key.UintVal() <= math.MaxInt64 {
			if idx, ok := f.byInt[int64(key.UintVal())]; ok {
				return idx, true
			}
		}
		idx, ok := f.byName[strconv.FormatUint(key.UintVal(), 10)]
		return idx, ok
	case cbor.KindNegInt:
		if key.NegIntVal() <= math.MaxInt64 {
			idx, ok := f.byInt[-1-int64(key.NegIntVal())]
			return idx, ok
		}
	}
	return -1, false
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
		return typeMismatch(val.Kind, "non-Tag", timeType)
	}
	t, err := cbor.AsTime(val)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(t))
	return nil
}

// decodeBigInt accepts a tag 2/3 bignum or, since deterministic modes
// write small bignums as plain integers (RFC 8949 §3.4.3, proposal 024),
// a major type 0/1 integer.
func decodeBigInt(val cbor.Value, target reflect.Value) error {
	if val.Kind != cbor.KindTag && val.Kind != cbor.KindUint && val.Kind != cbor.KindNegInt {
		return typeMismatch(val.Kind, "non-integer", bigIntType)
	}
	bi, err := cbor.AsBigIntAny(val)
	if err != nil {
		return err
	}
	target.Set(reflect.ValueOf(*bi))
	return nil
}

func decodeBigIntPtr(val cbor.Value, target reflect.Value) error {
	if val.Kind != cbor.KindTag && val.Kind != cbor.KindUint && val.Kind != cbor.KindNegInt {
		return typeMismatch(val.Kind, "non-integer", bigIntPtrType)
	}
	bi, err := cbor.AsBigIntAny(val)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
