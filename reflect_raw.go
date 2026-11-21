// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
	"github.com/jahkeup/corecbor/wire"
)

// Proposal 022: every Unmarshaler receives the bytes of its item
// exactly as they appear in the input. Targets that can reach an
// Unmarshaler are filled by walking the (already validated) source
// bytes; everything else keeps the Value-based path in
// reflect_decode.go.

var unmarshalerType = reflect.TypeFor[Unmarshaler]()

var rawTargetCache sync.Map // reflect.Type -> bool

// needsRaw reports whether decoding into t can reach an Unmarshaler,
// directly or through pointers, slices, arrays, maps or struct fields.
// Interface targets can't: their dynamic type comes from the data.
func needsRaw(t reflect.Type) bool {
	if v, ok := rawTargetCache.Load(t); ok {
		return v.(bool)
	}
	// Each top-level query uses its own visiting set, and only its own
	// result is cached: a type reached through a cycle may be reported
	// false mid-computation, which must not be cached.
	r := needsRawVisit(t, map[reflect.Type]bool{})
	rawTargetCache.Store(t, r)
	return r
}

func needsRawVisit(t reflect.Type, visiting map[reflect.Type]bool) bool {
	if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
		return true
	}
	if visiting[t] {
		return false
	}
	visiting[t] = true
	defer delete(visiting, t)

	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return needsRawVisit(t.Elem(), visiting)
	case reflect.Map:
		return needsRawVisit(t.Key(), visiting) || needsRawVisit(t.Elem(), visiting)
	case reflect.Struct:
		for _, fi := range getStructFields(t).list {
			if needsRawVisit(t.FieldByIndex(fi.index).Type, visiting) {
				return true
			}
		}
	}
	return false
}

// rawState carries what the byte walk needs to decode sub-items.
type rawState struct {
	unmarshalState
	opts rfc8949.DecodeOpts // knobs and limits; no arena or budget
}

// decodeItem decodes the item whose source bytes are span, as it
// decoded inside its parent.
func (r rawState) decodeItem(span []byte) (cbor.Value, error) {
	v, _, err := rfc8949.DecodeNested(span, r.opts)
	return v, err
}

// stripSelfDescribe drops leading self-describe tags (55799), as
// Decode does for the top-level item.
func stripSelfDescribe(span []byte) []byte {
	for {
		h := wire.ParseHead(span)
		if h.N == 0 || h.Major != wire.MajorTag || h.Arg != cbor.TagSelfDescribe {
			return span
		}
		span = span[h.N:]
	}
}

// value returns val if the walk kept it aligned with span, or decodes
// span otherwise.
func (r rawState) value(span []byte, val cbor.Value) (cbor.Value, error) {
	if val.Kind != cbor.KindInvalid {
		return val, nil
	}
	return r.decodeItem(span)
}

// rawToGo fills target from span, the source bytes of one well-formed
// item that Decode has already accepted, and val, the Value Decode
// produced for it (or the zero Value when the walk couldn't keep the
// two aligned, in which case span is decoded on demand). It mirrors
// valueToGo, except that Unmarshalers receive span itself.
func (r rawState) rawToGo(span []byte, val cbor.Value, target reflect.Value) error {
	return r.fill(span, val, target, needsRaw(target.Type()))
}

// fill is rawToGo with needsRaw(target.Type()) already known, so loops
// over many items of one type look it up once.
func (r rawState) fill(span []byte, val cbor.Value, target reflect.Value, raw bool) error {
	if !target.CanSet() {
		return fmt.Errorf("cbor: cannot set target of type %s", target.Type())
	}
	if !raw {
		v, err := r.value(span, val)
		if err != nil {
			return err
		}
		return r.valueToGo(v, target)
	}

	h := wire.ParseHead(span)
	if target.Kind() == reflect.Pointer {
		if h.Major == wire.MajorOther && h.AI == 22 { // null
			target.SetZero()
			return nil
		}
		if target.IsNil() {
			target.Set(reflect.New(target.Type().Elem()))
		}
		return r.rawToGo(span, val, target.Elem())
	}

	if target.CanAddr() {
		if u, ok := target.Addr().Interface().(Unmarshaler); ok {
			return u.UnmarshalCBOR(span)
		}
	}

	switch h.Major {
	case wire.MajorTag:
		var inner cbor.Value
		if val.Kind == cbor.KindTag {
			inner = val.TagInner()
		}
		return r.rawToGo(span[h.N:], inner, target)
	case wire.MajorArray:
		return r.rawArray(span, val, target)
	case wire.MajorMap:
		return r.rawMap(span, val, target)
	default:
		// Scalars (and null/undefined) into a container or struct
		// target: the Value path gives the same result and errors.
		v, err := r.value(span, val)
		if err != nil {
			return err
		}
		return r.valueToGo(v, target)
	}
}

// items splits a container's span into the spans of its items
// (key, value, key, value, ... for maps). Used only where the items
// must be seen before they are assigned (indefinite length, merging).
func (r rawState) items(c *rfc8949.Cursor, n int) ([][]byte, error) {
	var out [][]byte
	if n >= 0 {
		out = make([][]byte, 0, n)
	}
	for (n < 0 && !c.AtBreak()) || (n >= 0 && len(out) < n) {
		b, err := c.RawBytes()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (r rawState) rawArray(span []byte, val cbor.Value, target reflect.Value) error {
	switch target.Kind() {
	case reflect.Slice, reflect.Array:
	default:
		return typeMismatch("Array", target.Type())
	}
	c := rfc8949.NewCursor(span, r.opts)
	n, err := c.EnterArray()
	if err != nil {
		return err
	}
	var elems [][]byte
	if n < 0 {
		if elems, err = r.items(c, -1); err != nil {
			return err
		}
		n = len(elems)
	}
	var vals []cbor.Value
	if val.Kind == cbor.KindArray && len(val.Items) == n {
		vals = val.Items
	}
	next := func(i int) ([]byte, cbor.Value, error) {
		var v cbor.Value
		if vals != nil {
			v = vals[i]
		}
		if elems != nil {
			return elems[i], v, nil
		}
		b, err := c.RawBytes()
		return b, v, err
	}
	if target.Kind() == reflect.Slice {
		if target.IsNil() || target.Cap() < n {
			target.Set(reflect.MakeSlice(target.Type(), n, n))
		} else {
			target.SetLen(n)
		}
	}
	elemRaw := needsRaw(target.Type().Elem())
	for i := range n {
		b, v, err := next(i)
		if err != nil {
			return err
		}
		if i >= target.Len() {
			continue // Go array shorter than the input: extra items are skipped
		}
		if err := r.fill(b, v, target.Index(i), elemRaw); err != nil {
			return err
		}
	}
	return nil
}

// scalarKey identifies a scalar map key for duplicate merging. Two keys
// with equal scalarKeys are the keys the decoder merges: same kind and
// payload, floats compared with == (so -0 equals +0 and NaN never
// matches, since a NaN field makes the Go map key unequal to itself).
type scalarKey struct {
	kind cbor.Kind
	num  uint64
	f    float64
	s    string
}

func toScalarKey(v cbor.Value) (scalarKey, bool) {
	switch v.Kind {
	case cbor.KindUint, cbor.KindNegInt, cbor.KindBool, cbor.KindSimple:
		return scalarKey{kind: v.Kind, num: v.Num}, true
	case cbor.KindNull, cbor.KindUndefined:
		return scalarKey{kind: v.Kind}, true
	case cbor.KindBytes:
		return scalarKey{kind: v.Kind, s: string(v.Bstr)}, true
	case cbor.KindText:
		return scalarKey{kind: v.Kind, s: v.Str}, true
	case cbor.KindFloat32:
		return scalarKey{kind: v.Kind, f: float64(v.Float32Val())}, true
	case cbor.KindFloat64:
		return scalarKey{kind: v.Kind, f: v.Float64Val()}, true
	default:
		return scalarKey{}, false
	}
}

// sameKey reports whether a and b are the identical key (bit-for-bit
// for scalars, same kind otherwise); used to confirm that merged pairs
// line up with the decoded map.
func sameKey(a, b cbor.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	if _, scalar := toScalarKey(a); !scalar {
		return true
	}
	return a.Num == b.Num && a.Str == b.Str && bytes.Equal(a.Bstr, b.Bstr)
}

// mapTarget assigns one map entry to a Go map or struct target.
type mapTarget struct {
	target         reflect.Value
	fields         *structFields // struct targets
	fieldRaw       []bool        // struct targets: needsRaw per field
	keyRaw, valRaw bool          // map targets
}

// rawFields returns needsRaw for each field of the struct type t.
func rawFields(t reflect.Type, f *structFields) []bool {
	f.rawOnce.Do(func() {
		f.raw = make([]bool, len(f.list))
		for i, fi := range f.list {
			f.raw[i] = needsRaw(t.FieldByIndex(fi.index).Type)
		}
	})
	return f.raw
}

func (r rawState) rawMap(span []byte, val cbor.Value, target reflect.Value) error {
	mt := mapTarget{target: target}
	switch target.Kind() {
	case reflect.Map:
		if target.IsNil() {
			n := 0
			if val.Kind == cbor.KindMap {
				n = len(val.Pairs)
			}
			target.Set(reflect.MakeMapWithSize(target.Type(), n))
		}
		mt.keyRaw = needsRaw(target.Type().Key())
		mt.valRaw = needsRaw(target.Type().Elem())
	case reflect.Struct:
		mt.fields = getStructFields(target.Type())
		mt.fieldRaw = rawFields(target.Type(), mt.fields)
	default:
		return typeMismatch("Map", target.Type())
	}
	c := rfc8949.NewCursor(span, r.opts)
	n, err := c.EnterMap()
	if err != nil {
		return err
	}

	// Same pair count as the decoded map: nothing was merged, so the
	// pairs line up in order. Stream them, using the decoded keys and
	// values.
	if n >= 0 && val.Kind == cbor.KindMap && len(val.Pairs) == n {
		for i := range n {
			ks, err := c.RawBytes()
			if err != nil {
				return err
			}
			vs, err := c.RawBytes()
			if err != nil {
				return err
			}
			p := &val.Pairs[i]
			if err := r.assign(mt, p.Key, ks, vs, p.Value); err != nil {
				return err
			}
		}
		return nil
	}
	return r.rawMapMerged(c, n, val, mt)
}

// rawMapMerged handles maps whose duplicate keys the decoder merged
// (or indefinite-length maps): it decodes each key and merges
// duplicates the way the forgiving decoder does (the first key keeps
// its position and takes the last value; containers and tags are never
// merged), then assigns the merged entries in order.
func (r rawState) rawMapMerged(c *rfc8949.Cursor, n int, val cbor.Value, mt mapTarget) error {
	if n > 0 {
		n *= 2
	}
	kv, err := r.items(c, n)
	if err != nil {
		return err
	}
	type pair struct {
		key            cbor.Value
		keySpan, vSpan []byte
	}
	pairs := make([]pair, 0, len(kv)/2)
	var seen map[scalarKey]int
	if len(kv)/2 > 16 {
		seen = make(map[scalarKey]int, len(kv)/2)
	}
	for i := 0; i < len(kv); i += 2 {
		key, err := r.decodeItem(kv[i])
		if err != nil {
			return err
		}
		if sk, ok := toScalarKey(key); ok {
			j, dup := -1, false
			if seen != nil {
				j, dup = seen[sk]
			} else {
				for k := range pairs {
					if pk, ok := toScalarKey(pairs[k].key); ok && pk == sk {
						j, dup = k, true
						break
					}
				}
			}
			if dup {
				pairs[j].vSpan = kv[i+1]
				continue
			}
			if seen != nil {
				seen[sk] = len(pairs)
			}
		}
		pairs = append(pairs, pair{key: key, keySpan: kv[i], vSpan: kv[i+1]})
	}
	// The decoder's merge can differ (it buckets large maps by encoded
	// key bytes), so only borrow decoded values when they line up.
	aligned := val.Kind == cbor.KindMap && len(val.Pairs) == len(pairs)
	for i := 0; aligned && i < len(pairs); i++ {
		aligned = sameKey(pairs[i].key, val.Pairs[i].Key)
	}
	for i, p := range pairs {
		var v cbor.Value
		if aligned {
			v = val.Pairs[i].Value
		}
		if err := r.assign(mt, p.key, p.keySpan, p.vSpan, v); err != nil {
			return err
		}
	}
	return nil
}

// assign stores one entry (decoded key, key and value spans, decoded
// value or zero) into a map or struct target.
func (r rawState) assign(mt mapTarget, key cbor.Value, keySpan, span []byte, val cbor.Value) error {
	if mt.fields == nil {
		return r.assignMap(mt, key, keySpan, span, val)
	}
	idx, found := mt.fields.lookup(key)
	if !found {
		return nil
	}
	fi := &mt.fields.list[idx]
	fv, err := fieldByIndexAlloc(mt.target, fi.index)
	if err != nil {
		return err
	}
	if fi.hasTag {
		h := wire.ParseHead(span)
		if h.Major != wire.MajorTag {
			v, err := r.value(span, val)
			if err != nil {
				return err
			}
			return fmt.Errorf("cbor: field %q expects tag(%d) but got kind %d", fi.name, fi.tagID, v.Kind)
		}
		if h.Arg != fi.tagID {
			return fmt.Errorf("cbor: field %q expects tag(%d) but got tag(%d)", fi.name, fi.tagID, h.Arg)
		}
		span = span[h.N:]
		if val.Kind == cbor.KindTag {
			val = val.TagInner()
		} else {
			val = cbor.Value{}
		}
	}
	return r.fill(span, val, fv, mt.fieldRaw[idx])
}

func (r rawState) assignMap(mt mapTarget, key cbor.Value, keySpan, span []byte, val cbor.Value) error {
	target := mt.target
	keyType := target.Type().Key()
	k := reflect.New(keyType).Elem()
	if keyType.Kind() == reflect.Interface {
		goKey, err := r.keyToAny(key)
		if err != nil {
			return err
		}
		if err := setInterface(goKey, k); err != nil {
			return err
		}
	} else if err := r.fill(keySpan, key, k, mt.keyRaw); err != nil {
		return err
	}
	if !k.Comparable() {
		return typeMismatchf("map key of type %s is not comparable", k.Type())
	}
	v := reflect.New(target.Type().Elem()).Elem()
	if err := r.fill(span, val, v, mt.valRaw); err != nil {
		return err
	}
	target.SetMapIndex(k, v)
	return nil
}
