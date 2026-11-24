// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cbor"
)

// findValue enters the map at the start of src, finds key and decodes
// its value.
func findValue(src []byte, opts DecodeOpts, key string) (cbor.Value, error) {
	c := NewCursor(src, opts)
	if _, err := c.EnterMap(); err != nil {
		return cbor.Value{}, err
	}
	if err := c.FindMapKey(key); err != nil {
		return cbor.Value{}, err
	}
	return c.Decode()
}

// C7: FindMapKey resolves the key as Decode does: the last of repeated
// keys wins, a repeat is an error under RejectDuplicateMapKeys, and keys
// compare under the configured key identity.
func TestC7FindMapKeyMatchesDecode(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		opts DecodeOpts
		want cbor.Value // zero: want an error
		err  error
	}{
		{"last wins", "a2616101616102", DecodeOpts{}, cbor.Uint(2), nil},
		{"last wins indefinite map", "bf616101616102ff", DecodeOpts{}, cbor.Uint(2), nil},
		{"last wins among others", "a3616101616205616102", DecodeOpts{}, cbor.Uint(2), nil},
		{"reject", "a2616101616102", DecodeOpts{RejectDuplicateMapKeys: true}, cbor.Value{}, cbor.ErrDuplicateMapKey},
		{"strict rejects", "a2616101616102", StrictOpts(), cbor.Value{}, cbor.ErrDuplicateMapKey},
		{"non-shortest key is the same key", "a2616101780161" + "02", DecodeOpts{}, cbor.Uint(2), nil},
		{"non-shortest key found", "a178016105", DecodeOpts{}, cbor.Uint(5), nil},
		{"indefinite key found", "a17f6161ff05", DecodeOpts{}, cbor.Uint(5), nil},
		{"indefinite key with empty chunks", "a17f60616160ff05", DecodeOpts{}, cbor.Uint(5), nil},
		{"chunked indefinite key", "a17f6161606161ff05", DecodeOpts{}, cbor.Value{}, ErrKeyNotFound},
		{"chunked indefinite key aa", "a17f61616161ff05", DecodeOpts{}, cbor.Value{}, ErrKeyNotFound},
		{"indefinite key repeats", "a2616101 7f6161ff02", DecodeOpts{RejectDuplicateMapKeys: true}, cbor.Value{}, cbor.ErrDuplicateMapKey},
		{"encoded identity: other encoding is another key", "a2616101780161" + "02", DecodeOpts{KeyIdentity: KeyIdentityEncoded}, cbor.Uint(1), nil},
		{"encoded identity: byte-identical repeat", "a2616101616102", DecodeOpts{KeyIdentity: KeyIdentityEncoded}, cbor.Uint(2), nil},
		{"keep duplicates: first occurrence", "a2616101616102", DecodeOpts{KeepDuplicateMapKeys: true}, cbor.Uint(1), nil},
		{"not found", "a2616201616302", DecodeOpts{}, cbor.Value{}, ErrKeyNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := mustHex(stripSpaces(tc.src))
			got, err := findValue(src, tc.opts, "a")
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("FindMapKey: err = %v, want %v", err, tc.err)
				}
			} else if err != nil || !got.Equal(tc.want) {
				t.Fatalf("FindMapKey: %v, %v; want %v", got, err, tc.want)
			}
			// Decode agrees, unless the test is about keys Decode reads
			// differently (KeepDuplicateMapKeys keeps both).
			if tc.opts.KeepDuplicateMapKeys || tc.opts.KeyIdentity == KeyIdentityEncoded {
				return
			}
			v, _, derr := Decode(src, tc.opts)
			if errors.Is(tc.err, cbor.ErrDuplicateMapKey) {
				if !errors.Is(derr, cbor.ErrDuplicateMapKey) {
					t.Fatalf("Decode: err = %v, want ErrDuplicateMapKey", derr)
				}
				return
			}
			dv, ok := v.Get(cbor.Text("a"))
			if tc.err == nil && (!ok || !dv.Equal(tc.want)) || tc.err != nil && ok {
				t.Fatalf("Decode: a = %v (%v); FindMapKey %v, %v", dv, ok, got, err)
			}
		})
	}
}

// C7: under RejectDuplicateMapKeys a repeat the cursor has already
// passed still counts.
func TestC7FindMapKeyRejectsEarlierRepeat(t *testing.T) {
	src := mustHex("a3616101616202616103")
	c := NewCursor(src, DecodeOpts{RejectDuplicateMapKeys: true})
	if _, err := c.EnterMap(); err != nil {
		t.Fatal(err)
	}
	// Pass the first "a" entry by hand.
	for range 2 {
		if _, err := c.Skip(); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.FindMapKey("a"); !errors.Is(err, cbor.ErrDuplicateMapKey) {
		t.Fatalf("err = %v, want ErrDuplicateMapKey", err)
	}

	// Without the policy, the later entry is the one Decode keeps.
	c = NewCursor(src, DecodeOpts{})
	c.EnterMap() //nolint:errcheck
	c.Skip()     //nolint:errcheck
	c.Skip()     //nolint:errcheck
	if v, err := findCurrent(c, "a"); err != nil || !v.Equal(cbor.Uint(3)) {
		t.Fatalf("a = %v, %v; want 3", v, err)
	}
}

// C7: after FindMapKey the cursor reads the rest of the map normally.
func TestC7FindMapKeyThenContinue(t *testing.T) {
	src := mustHex("a4616101616202616103616304")
	c := NewCursor(src, DecodeOpts{})
	c.EnterMap() //nolint:errcheck
	if v, err := findCurrent(c, "a"); err != nil || !v.Equal(cbor.Uint(3)) {
		t.Fatalf("a = %v, %v; want 3", v, err)
	}
	if v, err := findCurrent(c, "c"); err != nil || !v.Equal(cbor.Uint(4)) {
		t.Fatalf("c = %v, %v; want 4", v, err)
	}
	if err := c.ExitMap(); err != nil || c.Offset() != len(src) {
		t.Fatalf("ExitMap: %v at %d", err, c.Offset())
	}
}

func findCurrent(c *Cursor, key string) (cbor.Value, error) {
	if err := c.FindMapKey(key); err != nil {
		return cbor.Value{}, err
	}
	return c.Decode()
}

func stripSpaces(s string) string {
	b := make([]byte, 0, len(s))
	for i := range len(s) {
		if s[i] != ' ' {
			b = append(b, s[i])
		}
	}
	return string(b)
}
