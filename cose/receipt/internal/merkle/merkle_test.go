// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package merkle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type inclusionProbe struct {
	LeafIdx   uint64   `json:"leafIdx"`
	TreeSize  uint64   `json:"treeSize"`
	Root      []byte   `json:"root"`
	LeafHash  []byte   `json:"leafHash"`
	Proof     [][]byte `json:"proof"`
	Desc      string   `json:"desc"`
	WantError bool     `json:"wantErr"`
}

type consistencyProbe struct {
	Size1     uint64   `json:"size1"`
	Size2     uint64   `json:"size2"`
	Root1     []byte   `json:"root1"`
	Root2     []byte   `json:"root2"`
	Proof     [][]byte `json:"proof"`
	Desc      string   `json:"desc"`
	WantError bool     `json:"wantErr"`
}

// rejectedEqualSize are CT happy-path probes that RFC 9162 §2.1.4.2
// fails (equal sizes, empty path); see testdata/ct/README.md.
var rejectedEqualSize = map[string]bool{
	"consistency/0/happy-path.json":                                      true,
	"consistency/additional/sizes-are-equal-one-and-proof-is-empty.json": true,
}

func probeFiles(t *testing.T, kind string) map[string][]byte {
	t.Helper()
	root := filepath.Join("testdata", "ct")
	out := map[string][]byte{}
	err := filepath.WalkDir(filepath.Join(root, kind), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("no %s probes found", kind)
	}
	return out
}

// TestMerkleCTVectors runs the Certificate Transparency reference probes
// (transparency-dev/merkle testdata): every happy path verifies and
// every mutation fails, except the equal-size consistency probes RFC
// 9162 itself rejects.
func TestMerkleCTVectors(t *testing.T) {
	for name, data := range probeFiles(t, "inclusion") {
		var p inclusionProbe
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err := VerifyInclusion(p.LeafIdx, p.TreeSize, p.LeafHash, p.Proof, p.Root)
		if p.WantError != (err != nil) {
			t.Errorf("%s (%s): err = %v, wantErr %v", name, p.Desc, err, p.WantError)
		}
	}
	for name, data := range probeFiles(t, "consistency") {
		var p consistencyProbe
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := p.WantError || rejectedEqualSize[name]
		err := VerifyConsistency(p.Size1, p.Size2, p.Root1, p.Root2, p.Proof)
		if want != (err != nil) {
			t.Errorf("%s (%s): err = %v, wantErr %v", name, p.Desc, err, want)
		}
	}
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMerkleRootVectors checks Merkle Tree Hashes against the CT
// reference roots for the standard eight-leaf input set.
func TestMerkleRootVectors(t *testing.T) {
	leaves := []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}
	roots := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	var tr Tree
	for _, l := range leaves {
		tr.Append(hx(t, l))
	}
	for n, want := range roots {
		got, err := tr.Root(uint64(n))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, hx(t, want)) {
			t.Errorf("MTH(D[0:%d]) = %x, want %s", n, got, want)
		}
	}
}

// TestMerkleExhaustive generates proofs from the tree definition
// (RFC 9162 §2.1.3.1, §2.1.4.1) for every leaf and size up to 64 and
// checks the verifiers accept them and reject a flipped bit.
func TestMerkleExhaustive(t *testing.T) {
	var tr Tree
	for i := range 64 {
		tr.Append([]byte{byte(i), byte(i >> 8), 0xaa})
	}
	for n := uint64(1); n <= tr.Size(); n++ {
		root, _ := tr.Root(n)
		for m := uint64(0); m < n; m++ {
			p, err := tr.InclusionProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			if len(p) != InclusionPathLen(m, n) {
				t.Fatalf("PATH(%d,%d) has %d entries, InclusionPathLen says %d", m, n, len(p), InclusionPathLen(m, n))
			}
			if err := VerifyInclusion(m, n, tr.leaves[m], p, root); err != nil {
				t.Fatalf("inclusion (%d,%d): %v", m, n, err)
			}
			if len(p) > 0 {
				bad := clonePath(p)
				bad[0][0] ^= 1
				if VerifyInclusion(m, n, tr.leaves[m], bad, root) == nil {
					t.Fatalf("inclusion (%d,%d) accepted a flipped bit", m, n)
				}
			}
		}
		for m := uint64(1); m < n; m++ {
			old, _ := tr.Root(m)
			p, err := tr.ConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			got, err := RootFromConsistency(m, n, old, p)
			if err != nil || !bytes.Equal(got, root) {
				t.Fatalf("consistency (%d,%d): root %x err %v", m, n, got, err)
			}
			bad := clonePath(p)
			bad[len(bad)-1][0] ^= 1
			if VerifyConsistency(m, n, old, root, bad) == nil {
				t.Fatalf("consistency (%d,%d) accepted a flipped bit", m, n)
			}
		}
	}
}

func clonePath(p [][]byte) [][]byte {
	out := make([][]byte, len(p))
	for i := range p {
		out[i] = bytes.Clone(p[i])
	}
	return out
}

// TestMerkleMalformed checks malformed proofs fail with ErrProof rather
// than panicking.
func TestMerkleMalformed(t *testing.T) {
	var tr Tree
	for i := range 9 {
		tr.Append([]byte{byte(i)})
	}
	root, _ := tr.Root(9)
	path, _ := tr.InclusionProof(5, 9)
	leaf := tr.leaves[5]
	long := make([][]byte, MaxInclusionPath+1)
	for i := range long {
		long[i] = make([]byte, HashSize)
	}
	cases := map[string]func() error{
		"index-equals-size": func() error { return VerifyInclusion(9, 9, leaf, path, root) },
		"index-off-by-one":  func() error { return VerifyInclusion(6, 9, leaf, path, root) },
		"short-path":        func() error { return VerifyInclusion(5, 9, leaf, path[:len(path)-1], root) },
		"extra-path":        func() error { return VerifyInclusion(5, 9, leaf, append(clonePath(path), root), root) },
		"33-byte-node": func() error {
			p := clonePath(path)
			p[0] = append(p[0], 0)
			return VerifyInclusion(5, 9, leaf, p, root)
		},
		"short-leaf-hash": func() error { return VerifyInclusion(5, 9, leaf[:31], path, root) },
		"path-over-cap":   func() error { return VerifyInclusion(0, 1<<63, leaf, long, root) },
		"size-zero":       func() error { return VerifyInclusion(0, 0, leaf, nil, root) },
		"wrong-root":      func() error { return VerifyInclusion(5, 9, leaf, path, leaf) },
		"cons-empty":      func() error { return VerifyConsistency(3, 9, root, root, nil) },
		"cons-size1-zero": func() error { return VerifyConsistency(0, 9, root, root, path) },
		"cons-equal":      func() error { return VerifyConsistency(9, 9, root, root, path) },
		"cons-33-byte": func() error {
			p := clonePath(path)
			p[1] = append(p[1], 0)
			return VerifyConsistency(3, 9, root, root, p)
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if err := f(); !errors.Is(err, ErrProof) {
				t.Fatalf("err = %v, want ErrProof", err)
			}
		})
	}
}

// TestRFC9942ExampleShapes checks that the (size, index) pairs in the
// RFC 9942 and RFC 9943 receipt examples carry the path lengths the
// RFCs show (their hashes are elided, so only shapes can be checked).
func TestRFC9942ExampleShapes(t *testing.T) {
	inclusion := []struct {
		index, size uint64
		want        int
		where       string
	}{
		{17, 20, 3, "RFC 9942 Figure 6"},
		{8, 9, 1, "RFC 9942 Figure 2, receipt 1"},
		{5, 6, 2, "RFC 9942 Figure 2, receipt 2"},
		{7, 8, 3, "RFC 9943 Figure 11"},
	}
	for _, c := range inclusion {
		if got := InclusionPathLen(c.index, c.size); got != c.want {
			t.Errorf("%s: path length for (%d,%d) = %d, want %d", c.where, c.index, c.size, got, c.want)
		}
	}
	var tr Tree
	for i := range 104 {
		tr.Append([]byte{byte(i)})
	}
	p, err := tr.ConsistencyProof(20, 104)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 6 {
		t.Errorf("RFC 9942 Figure 9: consistency path 20->104 has %d entries, want 6", len(p))
	}
}

func TestTreeErrors(t *testing.T) {
	var tr Tree
	tr.Append([]byte("a"))
	for name, err := range map[string]error{
		"root-beyond":        func() error { _, err := tr.Root(2); return err }(),
		"inclusion-beyond":   func() error { _, err := tr.InclusionProof(1, 1); return err }(),
		"consistency-zero":   func() error { _, err := tr.ConsistencyProof(0, 1); return err }(),
		"consistency-beyond": func() error { _, err := tr.ConsistencyProof(1, 2); return err }(),
	} {
		if !errors.Is(err, ErrProof) {
			t.Errorf("%s: err = %v, want ErrProof", name, err)
		}
	}
	if !strings.HasPrefix(ErrProof.Error(), "merkle:") {
		t.Error("ErrProof message prefix")
	}
}
