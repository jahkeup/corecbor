// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// fieldInfo describes one struct field as it appears on the wire.
type fieldInfo struct {
	index  []int // path through embedded structs, for FieldByIndex
	name   string
	intKey int64
	hasInt bool
	omit   bool
	tagID  uint64
	hasTag bool
	tagged bool // name came from a struct tag
}

// structFields is the cached wire layout of a struct type.
type structFields struct {
	list   []fieldInfo // in field-index order
	byName map[string]int
	byInt  map[int64]int

	rawOnce sync.Once
	raw     []bool // per field: needsRaw(field type), see reflect_raw.go
}

var fieldCache sync.Map // reflect.Type -> *structFields

// getStructFields returns the wire layout of struct type rt. Embedded
// structs are flattened using the encoding/json rules: the shallowest
// field wins, a tagged field beats an untagged one at the same depth,
// and any remaining tie drops every conflicting field. Fields of
// unexported embedded struct types and of embedded struct pointers are
// promoted like any other.
func getStructFields(rt reflect.Type) *structFields {
	if f, ok := fieldCache.Load(rt); ok {
		return f.(*structFields)
	}
	f, _ := fieldCache.LoadOrStore(rt, typeFields(rt))
	return f.(*structFields)
}

func typeFields(rt reflect.Type) *structFields {
	type scan struct {
		typ   reflect.Type
		index []int
	}
	var fields []fieldInfo
	current := []scan{}
	next := []scan{{typ: rt}}
	visited := map[reflect.Type]bool{}
	// count[t] and nextCount[t] detect the same embedded type reached
	// twice at one depth; its fields then conflict with themselves.
	var count, nextCount map[reflect.Type]int

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		for _, f := range current {
			if visited[f.typ] {
				continue
			}
			visited[f.typ] = true

			for i := range f.typ.NumField() {
				sf := f.typ.Field(i)
				if sf.Anonymous {
					t := sf.Type
					if t.Kind() == reflect.Pointer {
						t = t.Elem()
					}
					if !sf.IsExported() && t.Kind() != reflect.Struct {
						continue
					}
				} else if !sf.IsExported() {
					continue
				}

				tag := sf.Tag.Get("cbor")
				if tag == "-" {
					continue
				}
				name, opts, _ := strings.Cut(tag, ",")

				index := make([]int, len(f.index)+1)
				copy(index, f.index)
				index[len(f.index)] = i

				ft := sf.Type
				if ft.Name() == "" && ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}

				if name != "" || !sf.Anonymous || ft.Kind() != reflect.Struct {
					fi := fieldInfo{index: index, name: name, tagged: name != ""}
					if fi.name == "" {
						fi.name = strings.ToLower(sf.Name)
					}
					for opt := range strings.SplitSeq(opts, ",") {
						switch {
						case opt == "omitempty":
							fi.omit = true
						case strings.HasPrefix(opt, "tag="):
							if n, err := strconv.ParseUint(opt[4:], 10, 64); err == nil {
								fi.tagID = n
								fi.hasTag = true
							}
						}
					}
					if fi.tagged {
						if n, err := strconv.ParseInt(fi.name, 10, 64); err == nil {
							fi.intKey = n
							fi.hasInt = true
						}
					}
					fields = append(fields, fi)
					if count[f.typ] > 1 {
						// Two copies at the same depth annihilate each
						// other in the dominance pass below.
						fields = append(fields, fields[len(fields)-1])
					}
					continue
				}

				nextCount[ft]++
				if nextCount[ft] == 1 {
					next = append(next, scan{typ: ft, index: index})
				}
			}
		}
	}

	// Group by name, then by depth, then tagged first, so the dominant
	// field (if any) leads each group.
	slices.SortFunc(fields, func(a, b fieldInfo) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		if c := len(a.index) - len(b.index); c != 0 {
			return c
		}
		if a.tagged != b.tagged {
			if a.tagged {
				return -1
			}
			return 1
		}
		return slices.Compare(a.index, b.index)
	})

	out := fields[:0]
	for advance, i := 0, 0; i < len(fields); i += advance {
		fi := fields[i]
		for advance = 1; i+advance < len(fields); advance++ {
			if fields[i+advance].name != fi.name {
				break
			}
		}
		if advance == 1 {
			out = append(out, fi)
			continue
		}
		if dominant, ok := dominantField(fields[i : i+advance]); ok {
			out = append(out, dominant)
		}
	}
	fields = out
	slices.SortFunc(fields, func(a, b fieldInfo) int { return slices.Compare(a.index, b.index) })

	sf := &structFields{
		list:   fields,
		byName: make(map[string]int, len(fields)),
		byInt:  make(map[int64]int),
	}
	for i, fi := range fields {
		if fi.hasInt {
			sf.byInt[fi.intKey] = i
		} else {
			sf.byName[fi.name] = i
		}
	}
	return sf
}

// dominantField picks the winner among fields sharing a name, sorted
// by depth then tagged-first. There is none when the two leading
// candidates tie on both.
func dominantField(fields []fieldInfo) (fieldInfo, bool) {
	if len(fields) > 1 && len(fields[0].index) == len(fields[1].index) && fields[0].tagged == fields[1].tagged {
		return fieldInfo{}, false
	}
	return fields[0], true
}

// fieldByIndex returns the field at index for encoding. ok is false
// when an embedded pointer along the path is nil, in which case the
// field is omitted.
func fieldByIndex(v reflect.Value, index []int) (reflect.Value, bool) {
	for i, x := range index {
		if i > 0 && v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return reflect.Value{}, false
			}
			v = v.Elem()
		}
		v = v.Field(x)
	}
	return v, true
}

// fieldByIndexAlloc returns the field at index for decoding, allocating
// nil embedded pointers along the path.
func fieldByIndexAlloc(v reflect.Value, index []int) (reflect.Value, error) {
	for i, x := range index {
		if i > 0 && v.Kind() == reflect.Pointer {
			if v.IsNil() {
				if !v.CanSet() {
					return reflect.Value{}, typeMismatchf("cannot set embedded pointer to unexported struct %s", v.Type().Elem())
				}
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		v = v.Field(x)
	}
	return v, nil
}
