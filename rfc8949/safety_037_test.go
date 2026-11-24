// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

// Proposal 037: regression tests for the root-module release blockers.

// selfDescribeChain returns n self-describe tag heads (d9d9f7) followed
// by item.
func selfDescribeChain(n int, item ...byte) []byte {
	b := bytes.Repeat([]byte{0xd9, 0xd9, 0xf7}, n)
	return append(b, item...)
}

// C1: a long chain of leading self-describe tags is stripped without
// recursion, so it can't overflow the stack (about 6 MB of d9d9f7 used
// to crash the process).
func TestC1SelfDescribeChainNoStackOverflow(t *testing.T) {
	const n = 2 << 20 // 6 MiB of tag heads
	src := selfDescribeChain(n, 0x82, 0x01, 0x02)

	v, used, err := Decode(src, DecodeOpts{})
	if err != nil || used != len(src) || v.Kind != cbor.KindArray || len(v.Items) != 2 {
		t.Fatalf("Decode = %v, %d, %v; want [1, 2], %d, nil", v, used, err, len(src))
	}

	// The checking decoder walks the same bytes.
	if _, _, err := Decode(src, DecodeOpts{RequirePreferred: true, RequireSortedMapKeys: true}); err != nil {
		t.Fatalf("checking Decode: %v", err)
	}

	c := NewCursor(src, DecodeOpts{})
	if skipped, err := c.Skip(); err != nil || skipped != len(src) {
		t.Fatalf("Cursor.Skip = %d, %v; want %d, nil", skipped, err, len(src))
	}

	got, err := DecodeFrom(bytes.NewReader(src), DecodeOpts{})
	if err != nil || !got.Equal(v) {
		t.Fatalf("DecodeFrom = %v, %v; want %v", got, err, v)
	}
}

// C1: valid input keeps its result. Nested self-describe tags (inside
// another item) still count as tags and toward nesting depth.
func TestC1SelfDescribeChainResults(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  []byte
		want cbor.Value
	}{
		{"one", selfDescribeChain(1, 0x01), cbor.Uint(1)},
		{"three", selfDescribeChain(3, 0x01), cbor.Uint(1)},
		{"nested kept", []byte{0x81, 0xd9, 0xd9, 0xf7, 0x01}, cbor.MakeArray(cbor.MakeTag(55799, cbor.Uint(1)))},
		{"after other tag kept", []byte{0xc1, 0xd9, 0xd9, 0xf7, 0x01}, cbor.MakeTag(1, cbor.MakeTag(55799, cbor.Uint(1)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _, err := Decode(tc.src, DecodeOpts{})
			if err != nil || !v.Equal(tc.want) {
				t.Fatalf("Decode = %v, %v; want %v", v, err, tc.want)
			}
		})
	}
	// A non-shortest self-describe head is still checked.
	src := append([]byte{0xda, 0x00, 0x00, 0xd9, 0xf7}, selfDescribeChain(2, 0x01)...)
	if _, _, err := Decode(src, DecodeOpts{RejectNonShortest: true}); err == nil {
		t.Fatal("non-shortest self-describe head accepted under RejectNonShortest")
	}
	// Truncated after the chain.
	if _, _, err := Decode(selfDescribeChain(4), DecodeOpts{}); err == nil {
		t.Fatal("chain with no item accepted")
	}
}

// indefMap returns an indefinite-length map of n distinct uint keys.
func indefMap(n int) []byte {
	b := []byte{0xbf}
	for i := range n {
		b = append(b, 0x1a, byte(i>>24), byte(i>>16), byte(i>>8), byte(i), 0xf6)
	}
	return append(b, 0xff)
}

// C2: duplicate tracking in an indefinite-length map is not quadratic:
// it costs about what the same definite-length map costs.
func TestC2IndefiniteMapDuplicateCheckLinear(t *testing.T) {
	const n = 100_000
	indef := indefMap(n)
	def := append([]byte{0xba, 0, n >> 16, n >> 8 & 0xff, n & 0xff}, indef[1:len(indef)-1]...)
	for _, opts := range []DecodeOpts{{}, {RejectDuplicateMapKeys: true}, {KeyIdentity: KeyIdentityEncoded}} {
		start := time.Now()
		if _, _, err := Decode(def, opts); err != nil {
			t.Fatal(err)
		}
		defTime := time.Since(start)
		start = time.Now()
		v, _, err := Decode(indef, opts)
		if err != nil || len(v.Pairs) != n {
			t.Fatalf("indefinite: %d pairs, %v", len(v.Pairs), err)
		}
		if indefTime := time.Since(start); indefTime > 20*defTime+200*time.Millisecond {
			t.Fatalf("opts %+v: indefinite map took %v, definite %v", opts, indefTime, defTime)
		}
	}
}

// C2: comparing two large map keys that hold the same pairs in a
// different order is not quadratic either.
func TestC2MapKeyCompareLinear(t *testing.T) {
	const n = 20_000
	enc := func(rev bool) []byte {
		b := []byte{0xb9, n >> 8, n & 0xff}
		for i := range n {
			k := i
			if rev {
				k = n - 1 - i
			}
			b = append(b, 0x19, byte(k>>8), byte(k), 0xf6)
		}
		return b
	}
	src := append([]byte{0xa2}, enc(false)...)
	src = append(src, 0x01)
	src = append(src, enc(true)...)
	src = append(src, 0x02)
	start := time.Now()
	if _, _, err := Decode(src, DecodeOpts{RejectDuplicateMapKeys: true}); !errors.Is(err, cbor.ErrDuplicateMapKey) {
		t.Fatalf("err = %v, want ErrDuplicateMapKey", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("comparing two %d-pair map keys took %v", n, d)
	}
}

// C5: the memory budget is charged for everything Decode allocates, at
// its real size: indefinite-length containers and strings, short
// strings on the inline paths, tag content, and Value and MapEntry
// slots at their size.
func TestC5BudgetChargesRealSizes(t *testing.T) {
	rep := func(n int, b ...byte) []byte { return bytes.Repeat(b, n) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for _, tc := range []struct {
		name string
		src  []byte
		want int // bytes charged
	}{
		{"definite array", cat([]byte{0x98, 100}, rep(100, 0x00)), 100 * valueSize},
		{"indefinite array", cat([]byte{0x9f}, rep(100, 0x00), []byte{0xff}), 100 * valueSize},
		{"definite map", cat([]byte{0xb8, 20}, rep(20, 0x00, 0xf6)), 20 * pairSize},
		{"indefinite map", cat([]byte{0xbf, 0x00, 0xf6, 0x01, 0xf6, 0xff}), 2 * pairSize},
		{"indefinite bytes", cat([]byte{0x5f}, rep(10, 0x45, 1, 2, 3, 4, 5), []byte{0xff}), 50},
		{"indefinite text", cat([]byte{0x7f}, rep(10, 0x65, 'a', 'b', 'c', 'd', 'e'), []byte{0xff}), 50},
		{"array of short text", []byte{0x82, 0x63, 'a', 'b', 'c', 0x41, 0x00}, 2*valueSize + 3 + 1},
		{"map with short text key", []byte{0xa1, 0x63, 'a', 'b', 'c', 0x00}, pairSize + 3},
		{"tag", []byte{0xc1, 0x00}, valueSize},
		{"array of tags", []byte{0x82, 0xc1, 0x00, 0xc1, 0x00}, 4 * valueSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBudget(1 << 30)
			if _, _, err := Decode(tc.src, DecodeOpts{Budget: b}); err != nil {
				t.Fatal(err)
			}
			if b.Allocated != tc.want {
				t.Fatalf("charged %d, want %d", b.Allocated, tc.want)
			}
			if _, _, err := Decode(tc.src, DecodeOpts{Budget: NewBudget(tc.want - 1)}); !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
				t.Fatalf("budget %d: err = %v, want ErrMemoryBudgetExceeded", tc.want-1, err)
			}
		})
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// C4: DecodeFrom charges the bytes it buffers to the memory budget as it
// reads them, so a budget bounds what one item can make it read.
func TestC4DecodeFromBudgetBoundsReading(t *testing.T) {
	// An endless indefinite array of 4 MiB byte strings, each under the
	// default string and array limits.
	head := []byte{0x5a, 0x00, 0x40, 0x00, 0x00}
	r := &countingReader{r: io.MultiReader(bytes.NewReader([]byte{0x9f}), &endlessStrings{head: head, size: 4 << 20})}
	const budget = 1 << 20
	_, err := DecodeFrom(r, DecodeOpts{Budget: NewBudget(budget)})
	if !errors.Is(err, cbor.ErrMemoryBudgetExceeded) {
		t.Fatalf("err = %v, want ErrMemoryBudgetExceeded", err)
	}
	if r.n > 2*budget {
		t.Fatalf("read %d bytes under a %d-byte budget", r.n, budget)
	}

	// An item that fits is decoded, and the buffer counts toward the
	// budget alongside the decoded Value.
	src := []byte{0x43, 1, 2, 3}
	b := NewBudget(1 << 20)
	if _, err := DecodeFrom(bytes.NewReader(src), DecodeOpts{Budget: b}); err != nil {
		t.Fatal(err)
	}
	if b.Allocated != len(src)+3 {
		t.Fatalf("charged %d, want %d (buffer) + 3 (bytes)", b.Allocated, len(src))
	}
}

// endlessStrings yields head followed by size bytes, forever.
type endlessStrings struct {
	head []byte
	size int
	pos  int
}

func (e *endlessStrings) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		per := len(e.head) + e.size
		i := e.pos % per
		if i < len(e.head) {
			p[n] = e.head[i]
		} else {
			p[n] = 0xaa
		}
		n++
		e.pos++
	}
	return n, nil
}

// C2: duplicates in an indefinite-length map are still found, before
// and after the switch to hashing, under both key identities.
func TestC2IndefiniteMapDuplicates(t *testing.T) {
	for _, n := range []int{3, dedupThreshold, dedupThreshold + 1, 100} {
		for _, at := range []int{0, n - 1} {
			body := indefMap(n)
			body = body[: len(body)-1 : len(body)-1]
			// Repeat key `at` with value true just before the break: as a
			// non-shortest head (the same key in the data model) and
			// byte-identical.
			wide := append(append([]byte{}, body...), 0x1b, 0, 0, 0, 0, byte(at>>24), byte(at>>16), byte(at>>8), byte(at), 0xf5, 0xff)
			same := append(append([]byte{}, body...), 0x1a, byte(at>>24), byte(at>>16), byte(at>>8), byte(at), 0xf5, 0xff)

			v, _, err := Decode(wide, DecodeOpts{})
			if err != nil || len(v.Pairs) != n || v.Pairs[at].Value.Kind != cbor.KindBool {
				t.Fatalf("n=%d at=%d: last-wins: %d pairs, %v", n, at, len(v.Pairs), err)
			}
			if _, _, err := Decode(wide, DecodeOpts{RejectDuplicateMapKeys: true}); !errors.Is(err, cbor.ErrDuplicateMapKey) {
				t.Fatalf("n=%d at=%d: reject: %v", n, at, err)
			}
			// Under encoded identity the two encodings are different keys.
			v, _, err = Decode(wide, DecodeOpts{KeyIdentity: KeyIdentityEncoded, RejectDuplicateMapKeys: true})
			if err != nil || len(v.Pairs) != n+1 {
				t.Fatalf("n=%d at=%d: encoded: %d pairs, %v", n, at, len(v.Pairs), err)
			}
			if _, _, err := Decode(same, DecodeOpts{KeyIdentity: KeyIdentityEncoded, RejectDuplicateMapKeys: true}); !errors.Is(err, cbor.ErrDuplicateMapKey) {
				t.Fatalf("n=%d at=%d: encoded reject: %v", n, at, err)
			}
		}
	}
}
