// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package registry

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// generatedConsts parses tags_gen.go into name -> value.
func generatedConsts(t *testing.T) map[string]uint64 {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "tags_gen.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok {
				t.Fatalf("%s: non-literal value", vs.Names[0].Name)
			}
			n, err := strconv.ParseUint(lit.Value, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			out[vs.Names[0].Name] = n
		}
	}
	return out
}

// TestRegistryNamesFrozen: generated identifiers are API (proposal 026).
// Every name in names_frozen.txt — seeded from v0.2.2 — exists in
// tags_gen.go with the same tag number, and every generated constant is
// in the frozen list.
func TestRegistryNamesFrozen(t *testing.T) {
	gen := generatedConsts(t)
	f, err := os.Open("names_frozen.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	frozen := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		tag, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || len(fields) != 2 {
			t.Fatalf("bad frozen line %q", line)
		}
		frozen++
		if got, ok := gen["Tag"+fields[1]]; !ok || got != tag {
			t.Errorf("frozen Tag%s = %d: generated %d (present %v)", fields[1], tag, got, ok)
		}
	}
	if frozen != len(gen) {
		t.Errorf("%d frozen names, %d generated constants", frozen, len(gen))
	}
	// Spot-check names that existed in v0.2.2.
	for name, tag := range map[string]uint64{
		"TagDateTimeString":            0,
		"TagEncodedCBOR":               24,
		"TagCOSESign1":                 18,
		"TagSelfDescribe":              55799,
		"TagBinaryUUIDRFC9562Section4": 37,
	} {
		if gen[name] != tag {
			t.Errorf("%s = %d, want %d", name, gen[name], tag)
		}
	}
}

// TestRegistryNoUnassigned: the generator emits no constants for
// unassigned rows, and every registered row has a constant.
// TagReserved (tag 76, RFC 8746's reserved typed-array code point) is a
// registered row whose constant existed in v0.2.2, so it stays.
func TestRegistryNoUnassigned(t *testing.T) {
	gen := generatedConsts(t)
	for name := range gen {
		lower := strings.ToLower(name)
		if lower == "tagunassigned" || strings.HasPrefix(lower, "tagunassigned_") {
			t.Errorf("generated %s", name)
		}
	}
	byValue := map[uint64]bool{}
	for _, v := range gen {
		byValue[v] = true
	}
	for _, info := range AllTags() {
		if !byValue[info.Tag] {
			t.Errorf("registered tag %d has no generated constant", info.Tag)
		}
	}
}
