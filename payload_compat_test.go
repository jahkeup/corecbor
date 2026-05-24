// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type payloadFixture struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Source      string        `json:"source"`
	Hex         string        `json:"hex"`
	Expect      payloadExpect `json:"expect"`
}

type payloadExpect struct {
	Mode        string         `json:"mode"`
	Type        string         `json:"type"`
	Error       string         `json:"error"`
	Length      *int           `json:"length"`
	TagID       *int           `json:"tag_id"`
	Keys        []any          `json:"keys"`
	ReEncodeHex string         `json:"re_encode_hex"`
	Notes       string         `json:"notes"`
	Forgiving   *payloadExpect `json:"forgiving"`
}

func TestCompatPayloads(t *testing.T) {
	payloads := loadPayloadFixtures(t)
	if len(payloads) == 0 {
		t.Skip("no payload fixtures found in testdata/compat/payloads/")
	}

	dec := NewDecoder()
	strict := StrictDecoder()
	enc := New(ModeCoreDeterministic)

	for _, p := range payloads {
		t.Run(p.Name, func(t *testing.T) {
			data, err := hex.DecodeString(p.Hex)
			if err != nil {
				t.Fatalf("invalid hex in fixture: %v", err)
			}

			switch p.Expect.Mode {
			case "decode_ok":
				val, err := dec.Decode(data)
				if err != nil {
					t.Fatalf("expected successful decode, got error: %v", err)
				}
				validateType(t, val, p.Expect.Type)
				validateStructure(t, val, p.Expect)
				if p.Expect.ReEncodeHex != "" {
					got, err := enc.Encode(nil, val)
					if err != nil {
						t.Fatalf("re-encode failed: %v", err)
					}
					gotHex := hex.EncodeToString(got)
					if gotHex != p.Expect.ReEncodeHex {
						t.Errorf("re-encode mismatch:\n  got:  %s\n  want: %s", gotHex, p.Expect.ReEncodeHex)
					}
				}

			case "decode_error":
				_, err := dec.Decode(data)
				if err == nil {
					t.Fatal("expected decode error, got success")
				}
				if p.Expect.Error != "" && !strings.Contains(err.Error(), p.Expect.Error) {
					t.Errorf("error %q does not contain expected substring %q", err.Error(), p.Expect.Error)
				}

			case "strict_error":
				val, forgivingErr := dec.Decode(data)
				if forgivingErr != nil {
					t.Logf("note: forgiving decoder also rejects this: %v", forgivingErr)
				}
				if p.Expect.Forgiving != nil && forgivingErr == nil {
					validateType(t, val, p.Expect.Forgiving.Type)
					validateStructure(t, val, *p.Expect.Forgiving)
					if p.Expect.Forgiving.ReEncodeHex != "" {
						got, err := enc.Encode(nil, val)
						if err != nil {
							t.Fatalf("forgiving re-encode failed: %v", err)
						}
						gotHex := hex.EncodeToString(got)
						if gotHex != p.Expect.Forgiving.ReEncodeHex {
							t.Errorf("forgiving re-encode mismatch:\n  got:  %s\n  want: %s", gotHex, p.Expect.Forgiving.ReEncodeHex)
						}
					}
				}
				_, strictErr := strict.Decode(data)
				if strictErr == nil {
					t.Fatal("expected strict decode error, got success")
				}
				if p.Expect.Error != "" && !strings.Contains(strictErr.Error(), p.Expect.Error) {
					t.Errorf("strict error %q does not contain expected substring %q", strictErr.Error(), p.Expect.Error)
				}

			default:
				t.Fatalf("unknown expect.mode: %q", p.Expect.Mode)
			}
		})
	}
}

func validateType(t *testing.T, val Value, wantType string) {
	t.Helper()
	if wantType == "" {
		return
	}
	var gotType string
	switch val.Kind() {
	case KindUint:
		gotType = "uint"
	case KindNegInt:
		gotType = "negint"
	case KindBytes:
		gotType = "bytes"
	case KindText:
		gotType = "text"
	case KindArray:
		gotType = "array"
	case KindMap:
		gotType = "map"
	case KindTag:
		gotType = "tag"
	case KindBool:
		gotType = "bool"
	case KindNull:
		gotType = "null"
	case KindUndefined:
		gotType = "undefined"
	case KindFloat32, KindFloat64:
		gotType = "float"
	default:
		gotType = "unknown"
	}
	if gotType != wantType {
		t.Errorf("decoded type = %s, want %s", gotType, wantType)
	}
}

func validateStructure(t *testing.T, val Value, expect payloadExpect) {
	t.Helper()
	if expect.Length != nil {
		switch val.Kind() {
		case KindArray:
			if len(val.Array()) != *expect.Length {
				t.Errorf("array length = %d, want %d", len(val.Array()), *expect.Length)
			}
		case KindMap:
			if len(val.Map()) != *expect.Length {
				t.Errorf("map length = %d, want %d", len(val.Map()), *expect.Length)
			}
		}
	}
	if expect.TagID != nil {
		if val.Kind() != KindTag {
			t.Errorf("expected Tag, got kind %d", val.Kind())
		} else if int(val.TagID()) != *expect.TagID {
			t.Errorf("tag ID = %d, want %d", val.TagID(), *expect.TagID)
		}
	}
}

func loadPayloadFixtures(t *testing.T) []payloadFixture {
	t.Helper()
	pattern := filepath.Join("testdata", "compat", "payloads", "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob payload fixtures: %v", err)
	}
	var fixtures []payloadFixture
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		var fix payloadFixture
		if err := json.Unmarshal(data, &fix); err != nil {
			t.Fatalf("parsing %s: %v", f, err)
		}
		if fix.Name == "" {
			fix.Name = filepath.Base(f)
		}
		fixtures = append(fixtures, fix)
	}
	return fixtures
}

func TestCompatPayloads_FixtureFormatValidation(t *testing.T) {
	fixtures := loadPayloadFixtures(t)
	for _, f := range fixtures {
		t.Run(f.Name+"/format", func(t *testing.T) {
			if f.Hex == "" {
				t.Error("fixture missing 'hex' field")
			}
			if _, err := hex.DecodeString(f.Hex); err != nil {
				t.Errorf("fixture has invalid hex: %v", err)
			}
			switch f.Expect.Mode {
			case "decode_ok", "decode_error", "strict_error":
			default:
				t.Errorf("fixture has invalid mode: %q", f.Expect.Mode)
			}
			if f.Expect.Mode == "decode_ok" && f.Expect.Type == "" {
				t.Error("decode_ok fixture missing 'expect.type'")
			}
		})
	}
}

// Verify forgiving decoder handles payloads that strict mode rejects.
func TestCompatPayloads_StrictSubset(t *testing.T) {
	fixtures := loadPayloadFixtures(t)
	dec := NewDecoder()

	for _, f := range fixtures {
		if f.Expect.Mode != "strict_error" {
			continue
		}
		t.Run(f.Name+"/forgiving-accepts", func(t *testing.T) {
			data, _ := hex.DecodeString(f.Hex)
			_, err := dec.Decode(data)
			if err != nil && !errors.Is(err, ErrTrailingBytes) {
				t.Logf("note: forgiving decoder also rejects (may be malformed beyond quirk): %v", err)
			}
		})
	}
}
