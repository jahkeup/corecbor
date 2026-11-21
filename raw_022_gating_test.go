// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Gating acceptance tests for proposal 022.

func TestRawMessagePreservesUnsorted(t *testing.T) {
	var s struct {
		R RawMessage `cbor:"r"`
	}
	if err := Unmarshal(mustHex(t, "a16172a2616201616102"), &s); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s.R) != "a2616201616102" {
		t.Fatalf("RawMessage = %x, want a2616201616102", []byte(s.R))
	}
}

func TestCursorBytesZeroAlloc(t *testing.T) {
	src := mustHex(t, "43a10126") // h'a10126' (a COSE protected header)
	dec := NewDecoder()
	var got []byte
	allocs := testing.AllocsPerRun(100, func() {
		c := dec.Cursor(src)
		got, _ = c.Bytes()
	})
	if hex.EncodeToString(got) != "a10126" {
		t.Fatalf("Bytes = %x", got)
	}
	if allocs != 0 {
		t.Fatalf("Cursor.Bytes allocates %v times", allocs)
	}
}

// WebAuthn authenticator data embeds a COSE_Key followed directly by an
// extensions map, with no length prefix (WebAuthn §6.1, §6.5.1). The
// fixture follows that layout: rpIdHash ‖ flags(UP|UV|AT|ED) ‖
// signCount ‖ aaguid ‖ credIdLen ‖ credId ‖ COSE_Key ‖ extensions.
// It is synthetic (fixed bytes in the real layout), not captured from
// an authenticator.
func TestDecodePrefixWebAuthnAuthData(t *testing.T) {
	coseKey := mustHex(t, "a5"+
		"0102"+ // 1 (kty): 2 (EC2)
		"0326"+ // 3 (alg): -7 (ES256)
		"2001"+ // -1 (crv): 1 (P-256)
		"215820"+"65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"+ // -2 (x)
		"225820"+"1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c") // -3 (y)
	ext := mustHex(t, "a16b6372656450726f7465637402") // {"credProtect": 2}

	var authData []byte
	authData = append(authData, bytes.Repeat([]byte{0x49}, 32)...) // rpIdHash
	authData = append(authData, 0xc5)                              // flags
	authData = append(authData, 0, 0, 0, 7)                        // signCount
	authData = append(authData, bytes.Repeat([]byte{0xaa}, 16)...) // aaguid
	authData = append(authData, 0, 4, 1, 2, 3, 4)                  // credIdLen=4, credId
	keyOff := len(authData)
	authData = append(authData, coseKey...)
	authData = append(authData, ext...)

	v, rest, err := NewDecoder().DecodePrefix(authData[keyOff:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, ext) {
		t.Fatalf("rest = %x, want extensions %x", rest, ext)
	}
	if raw := authData[keyOff : len(authData)-len(rest)]; !bytes.Equal(raw, coseKey) {
		t.Fatalf("COSE_Key span = %x", raw)
	}
	if v.Kind != KindMap || len(v.Pairs) != 5 {
		t.Fatalf("COSE_Key decoded as %s", DiagnosticValue(v))
	}
}
