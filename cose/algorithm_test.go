// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAlgorithmStringCoversAllConstants parses the package source and
// checks that every exported Algorithm constant has a String case, so a
// new constant can't silently print "unknown".
func TestAlgorithmStringCoversAllConstants(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				id, ok := vs.Type.(*ast.Ident)
				if !ok || id.Name != "Algorithm" {
					continue
				}
				for _, n := range vs.Names {
					if n.IsExported() {
						names = append(names, n.Name)
					}
				}
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("found no Algorithm constants")
	}
	values := algorithmConstants()
	for _, name := range names {
		alg, ok := values[name]
		if !ok {
			t.Errorf("%s: add it to algorithmConstants in this test", name)
			continue
		}
		if s := alg.String(); s == "unknown" {
			t.Errorf("%s (%d).String() = %q", name, int64(alg), s)
		}
	}
}

// algorithmConstants maps each exported Algorithm constant's name to its
// value. TestAlgorithmStringCoversAllConstants fails if one is missing.
func algorithmConstants() map[string]Algorithm {
	return map[string]Algorithm{
		"AlgEdDSA":                           AlgEdDSA,
		"AlgES256":                           AlgES256,
		"AlgES384":                           AlgES384,
		"AlgES512":                           AlgES512,
		"AlgA128GCM":                         AlgA128GCM,
		"AlgA192GCM":                         AlgA192GCM,
		"AlgA256GCM":                         AlgA256GCM,
		"AlgHMAC256_64":                      AlgHMAC256_64,
		"AlgHMAC256":                         AlgHMAC256,
		"AlgHMAC384":                         AlgHMAC384,
		"AlgHMAC512":                         AlgHMAC512,
		"AlgDirect":                          AlgDirect,
		"AlgA128KW":                          AlgA128KW,
		"AlgA192KW":                          AlgA192KW,
		"AlgA256KW":                          AlgA256KW,
		"AlgECDH_ES_HKDF_256":                AlgECDH_ES_HKDF_256,
		"AlgPBES2_HS256_A128KW":              AlgPBES2_HS256_A128KW,
		"AlgHPKEBaseP256SHA256AES128GCM":     AlgHPKEBaseP256SHA256AES128GCM,
		"AlgPS256":                           AlgPS256,
		"AlgPS384":                           AlgPS384,
		"AlgPS512":                           AlgPS512,
		"AlgRS256":                           AlgRS256,
		"AlgRS384":                           AlgRS384,
		"AlgRS512":                           AlgRS512,
		"AlgSHA1":                            AlgSHA1,
		"AlgSHA256_64":                       AlgSHA256_64,
		"AlgSHA256":                          AlgSHA256,
		"AlgSHA512_256":                      AlgSHA512_256,
		"AlgSHA384":                          AlgSHA384,
		"AlgSHA512":                          AlgSHA512,
		"AlgHPKE_Base_P256_SHA256_AES128GCM": AlgHPKE_Base_P256_SHA256_AES128GCM,
	}
}
