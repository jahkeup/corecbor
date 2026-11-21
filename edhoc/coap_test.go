// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9668 §3.4, Figure 4: the payload of an EDHOC + OSCORE request is
// EDHOC message_3 followed by the OSCORE ciphertext, and C_R is the
// OSCORE 'kid' (Sender ID 0x01, OSCORE option value 0x090001).
func TestCoAP_RFC9668Figure4(t *testing.T) {
	msg3 := unhex(t, "52d5535f3147e85f1cfacd9e78abf9e0a81bbf")
	ciphertext := unhex(t, "612f1092f1776f1c1668b3825e")
	want := unhex(t, "52d5535f3147e85f1cfacd9e78abf9e0a81bbf612f1092f1776f1c1668b3825e")

	got, err := CombinedPayload(msg3, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("CombinedPayload = %x, want %x", got, want)
	}

	// The full CoAP message from Figure 4: payload follows the 0xff marker.
	msg := unhex(t, "44025d1f0000397493090001c0ff52d5535f3147e85f1cfacd9e78abf9e0a81bbf612f1092f1776f1c1668b3825e")
	payload := msg[bytes.IndexByte(msg, 0xff)+1:]
	m3, ct, err := SplitCombinedPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m3, msg3) || !bytes.Equal(ct, ciphertext) {
		t.Fatalf("SplitCombinedPayload = %x, %x", m3, ct)
	}
	// OSCORE option 0x090001: flags 0x09 (n=1: Partial IV 0x00; k set),
	// kid 0x01, which is C_R. In the sequential flow the same C_R is the
	// CBOR integer 1 prepended to message_3 (RFC 9668 §3.4).
	kid := []byte{0x01}
	if got := CoAPMessageWithCID(ConnectionID(kid), msg3); !bytes.Equal(got[:1], []byte{0x01}) {
		t.Fatalf("sequential prefix = %x, want 01", got[:1])
	}
}

func TestCoAP_Prefixes(t *testing.T) {
	msg := []byte{0x58, 0x01, 0xaa}
	cases := []struct {
		name   string
		cid    ConnectionID
		prefix string
	}{
		{"int 1", ConnectionID{0x01}, "01"},
		{"int -1 (h'20')", ConnectionID{0x20}, "20"},
		{"int -24 (h'37')", ConnectionID{0x37}, "37"},
		{"one-byte bstr", ConnectionID{0x18}, "4118"},
		{"two-byte bstr", ConnectionID{0x40, 0x41}, "424041"},
		{"empty bstr", ConnectionID{}, "40"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := CoAPMessageWithCID(tc.cid, msg)
			if got := hex.EncodeToString(p[:len(p)-len(msg)]); got != tc.prefix {
				t.Fatalf("prefix = %s, want %s", got, tc.prefix)
			}
			cid, isMsg1, rest, err := SplitCoAPPrefix(p)
			if err != nil || isMsg1 || !bytes.Equal(cid, tc.cid) || !bytes.Equal(rest, msg) {
				t.Fatalf("SplitCoAPPrefix = %x, %v, %x, %v", cid, isMsg1, rest, err)
			}
		})
	}

	p := CoAPMessage1(msg)
	if p[0] != 0xf5 {
		t.Fatalf("message_1 prefix = %x, want f5", p[0])
	}
	cid, isMsg1, rest, err := SplitCoAPPrefix(p)
	if err != nil || !isMsg1 || cid != nil || !bytes.Equal(rest, msg) {
		t.Fatalf("SplitCoAPPrefix(message_1) = %x, %v, %x, %v", cid, isMsg1, rest, err)
	}
}

func TestCoAP_Errors(t *testing.T) {
	for name, p := range map[string][]byte{
		"empty":           nil,
		"false":           {0xf4},
		"uint 24":         {0x18, 0x18},
		"text":            {0x61, 'a'},
		"truncated bstr":  {0x42, 0x01},
		"indefinite bstr": {0x5f, 0x41, 0x01, 0xff},
		"reserved AI 29":  {0x5d},
		"non-shortest":    {0x58, 0x01, 0xaa},
	} {
		if _, _, _, err := SplitCoAPPrefix(p); !errors.Is(err, ErrMessageFormat) {
			t.Errorf("SplitCoAPPrefix(%s) err = %v, want ErrMessageFormat", name, err)
		}
	}
	for name, p := range map[string][]byte{
		"empty":         nil,
		"not bstr":      {0x01, 0x02},
		"truncated":     {0x45, 0x01},
		"no ciphertext": {0x41, 0x01},
	} {
		if _, _, err := SplitCombinedPayload(p); !errors.Is(err, ErrMessageFormat) {
			t.Errorf("SplitCombinedPayload(%s) err = %v, want ErrMessageFormat", name, err)
		}
	}
	if _, err := CombinedPayload([]byte{0x41, 0x01, 0x02}, []byte{0x01}); !errors.Is(err, ErrMessageFormat) {
		t.Errorf("CombinedPayload(two items) err = %v, want ErrMessageFormat", err)
	}
	if _, err := CombinedPayload([]byte{0x41, 0x01}, nil); !errors.Is(err, ErrMessageFormat) {
		t.Errorf("CombinedPayload(no ciphertext) err = %v, want ErrMessageFormat", err)
	}
}

// A forward-flow handshake framed as CoAP payloads: the server keeps
// sessions by C_R and dispatches each request by its prefix, as RFC 9528
// Appendix A.2.1 describes. message_3 arrives once prefixed with C_R and
// once in a combined EDHOC + OSCORE request, dispatched by the 'kid'.
func TestCoAP_ForwardFlowDispatch(t *testing.T) {
	for _, combined := range []bool{false, true} {
		ini, res := pair(t, []byte{0x0a}, []byte{0x27}, nil)
		sessions := map[string]*Responder{}

		msg1, err := ini.CreateMessage1()
		if err != nil {
			t.Fatal(err)
		}
		cid, isMsg1, body, err := SplitCoAPPrefix(CoAPMessage1(msg1))
		if err != nil || !isMsg1 || cid != nil {
			t.Fatalf("message_1 prefix: %x %v %v", cid, isMsg1, err)
		}
		msg2, err := res.ProcessMessage1(body)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.PeerConnectionID(); !bytes.Equal(got, []byte{0x0a}) {
			t.Fatalf("Responder.PeerConnectionID = %x", got)
		}
		sessions[string(res.ConnectionID())] = res

		msg3, err := ini.ProcessMessage2(msg2)
		if err != nil {
			t.Fatal(err)
		}
		cR := ini.PeerConnectionID()
		if !bytes.Equal(cR, []byte{0x27}) || !bytes.Equal(ini.ConnectionID(), []byte{0x0a}) {
			t.Fatalf("Initiator IDs: own %x peer %x", ini.ConnectionID(), cR)
		}

		var got *Responder
		if combined {
			payload, err := CombinedPayload(msg3, []byte{0xde, 0xad, 0xbe, 0xef})
			if err != nil {
				t.Fatal(err)
			}
			kid := cR // the OSCORE 'kid' the client sends
			m3, ct, err := SplitCombinedPayload(payload)
			if err != nil || !bytes.Equal(ct, []byte{0xde, 0xad, 0xbe, 0xef}) {
				t.Fatalf("SplitCombinedPayload: %x %v", ct, err)
			}
			got, body = sessions[string(ConnectionID(kid))], m3
		} else {
			cid, isMsg1, b, err := SplitCoAPPrefix(CoAPMessageWithCID(cR, msg3))
			if err != nil || isMsg1 {
				t.Fatalf("message_3 prefix: %v %v", isMsg1, err)
			}
			got, body = sessions[string(cid)], b
		}
		if got != res {
			t.Fatalf("combined=%v: dispatch found no session for C_R %x", combined, cR)
		}
		if err := got.ProcessMessage3(body); err != nil {
			t.Fatalf("combined=%v: ProcessMessage3: %v", combined, err)
		}
		a, err := ini.ExportOSCORE()
		if err != nil {
			t.Fatal(err)
		}
		b, err := res.ExportOSCORE()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a.MasterSecret, b.MasterSecret) || !bytes.Equal(a.SenderID, b.RecipientID) {
			t.Fatalf("combined=%v: OSCORE contexts disagree", combined)
		}
	}
}

// Reverse flow (RFC 9528 Appendix A.2.2): the client is the Responder
// and prepends C_I to message_2.
func TestCoAP_ReverseFlowPrefix(t *testing.T) {
	ini, res := pair(t, []byte{0x05}, []byte{0x06}, nil)
	msg1, err := ini.CreateMessage1()
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := res.ProcessMessage1(msg1)
	if err != nil {
		t.Fatal(err)
	}
	cid, isMsg1, body, err := SplitCoAPPrefix(CoAPMessageWithCID(res.PeerConnectionID(), msg2))
	if err != nil || isMsg1 || !bytes.Equal(cid, ini.ConnectionID()) {
		t.Fatalf("reverse prefix = %x, %v, %v; want C_I %x", cid, isMsg1, err, ini.ConnectionID())
	}
	if _, err := ini.ProcessMessage2(body); err != nil {
		t.Fatal(err)
	}
}

func FuzzSplitCoAPPrefix(f *testing.F) {
	for _, s := range []string{"f5", "01", "20", "4118", "424041", "40", "f4", "1818", "5f4101ff", ""} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		cid, isMsg1, rest, err := SplitCoAPPrefix(p)
		if err != nil {
			return
		}
		var again []byte
		if isMsg1 {
			again = CoAPMessage1(rest)
		} else {
			again = CoAPMessageWithCID(cid, rest)
		}
		// Re-framing reproduces the input unless the identifier was a
		// byte string that encodes as an integer (encodeCID prefers ints).
		if !bytes.Equal(again, p) && (len(cid) != 1 || !isOneByteInt(cid[0])) {
			t.Fatalf("reframe %x -> %x", p, again)
		}
	})
}

func FuzzSplitCombinedPayload(f *testing.F) {
	for _, s := range []string{"52d5535f3147e85f1cfacd9e78abf9e0a81bbf612f1092f1776f1c1668b3825e", "4101ff", "41", ""} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		m3, ct, err := SplitCombinedPayload(p)
		if err != nil {
			return
		}
		again, err := CombinedPayload(m3, ct)
		if err != nil || !bytes.Equal(again, p) {
			t.Fatalf("recombine %x -> %x, %v", p, again, err)
		}
	})
}
