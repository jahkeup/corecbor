// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func edPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// pair builds a pinned-key method 0 suite 0 Initiator and Responder.
func pair(t *testing.T, ci, cr []byte, mut func(*InitiatorConfig, *ResponderConfig)) (*Initiator, *Responder) {
	t.Helper()
	iPriv, iPub := edPair(t)
	rPriv, rPub := edPair(t)
	ic := InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: ci}
	rc := ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, PeerPublic: iPub, ConnectionID: cr}
	if mut != nil {
		mut(&ic, &rc)
	}
	ini, err := NewInitiator(ic)
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(rc)
	if err != nil {
		t.Fatal(err)
	}
	return ini, res
}

func TestRFC_HandshakeWithEAD(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
		ic.EAD1 = []EADItem{{Label: 7, Value: []byte("hello")}}
		ic.EAD3 = []EADItem{{Label: 9, Critical: true}}
		rc.EAD2 = []EADItem{{Label: 8}}
		rc.AcceptCriticalEAD = func(e EADItem) bool { return e.Label == 9 }
	})
	m1, err := ini.CreateMessage1()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := res.ProcessMessage1(m1)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.PeerEAD(); len(got) != 1 || got[0].Label != 7 || string(got[0].Value) != "hello" {
		t.Fatalf("EAD_1 = %+v", got)
	}
	m3, err := ini.ProcessMessage2(m2)
	if err != nil {
		t.Fatal(err)
	}
	if got := ini.PeerEAD(); len(got) != 1 || got[0].Label != 8 || got[0].Value != nil {
		t.Fatalf("EAD_2 = %+v", got)
	}
	if err := res.ProcessMessage3(m3); err != nil {
		t.Fatal(err)
	}
	if got := res.PeerEAD(); len(got) != 1 || !got[0].Critical || got[0].Label != 9 {
		t.Fatalf("EAD_3 = %+v", got)
	}
	a, _ := ini.Export(5, []byte("ctx"), 20)
	b, _ := res.Export(5, []byte("ctx"), 20)
	if len(a) != 20 || !bytes.Equal(a, b) {
		t.Fatal("exporter mismatch")
	}
}

func TestRFC_UnknownCriticalEADAborts(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, _ *ResponderConfig) {
		ic.EAD1 = []EADItem{{Label: 99, Critical: true}}
	})
	m1, _ := ini.CreateMessage1()
	if _, err := res.ProcessMessage1(m1); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v, want ErrAuthentication", err)
	}
}

func TestRFC_ConnectionIDsMustDiffer(t *testing.T) {
	ini, res := pair(t, []byte{5}, []byte{5}, nil)
	m1, _ := ini.CreateMessage1()
	if _, err := res.ProcessMessage1(m1); !errors.Is(err, ErrStateViolation) {
		t.Fatalf("Responder with C_R == C_I: err = %v", err)
	}
	// A random C_R avoids C_I.
	for range 50 {
		ini, res := pair(t, []byte{0x00}, nil, func(_ *InitiatorConfig, rc *ResponderConfig) {
			rc.Rand = bytes.NewReader(bytes.Repeat([]byte{0, 0, 1}, 64)) // first draw maps to C_I
		})
		m1, _ := ini.CreateMessage1()
		m2, err := res.ProcessMessage1(m1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ini.ProcessMessage2(m2); err != nil {
			t.Fatal(err)
		}
		o, _ := ini.ExportOSCORE()
		if bytes.Equal(o.SenderID, o.RecipientID) {
			t.Fatal("C_R == C_I")
		}
	}
}

func TestRFC_FailureIsTerminal(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, nil)
	m1, _ := ini.CreateMessage1()
	m2, _ := res.ProcessMessage1(m1)
	bad := bytes.Clone(m2)
	bad[len(bad)-1] ^= 1
	if _, err := ini.ProcessMessage2(bad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered message_2: %v", err)
	}
	// The genuine message_2 is refused after a failure.
	if _, err := ini.ProcessMessage2(m2); !errors.Is(err, ErrStateViolation) {
		t.Fatalf("after failure: %v", err)
	}
	if _, err := ini.ExportOSCORE(); !errors.Is(err, ErrStateViolation) {
		t.Fatalf("export after failure: %v", err)
	}
	if ini.s.prk2e != nil || ini.s.eph != nil {
		t.Fatal("secrets not zeroized on failure")
	}
}

func TestRFC_CloseZeroizes(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, nil)
	m1, _ := ini.CreateMessage1()
	m2, _ := res.ProcessMessage1(m1)
	m3, _ := ini.ProcessMessage2(m2)
	if err := res.ProcessMessage3(m3); err != nil {
		t.Fatal(err)
	}
	out := ini.s.prkOut
	ini.Close()
	ini.Close() // idempotent
	if !bytes.Equal(out, make([]byte, len(out))) || ini.s.prkOut != nil {
		t.Fatal("PRK_out not zeroized")
	}
	if _, err := ini.PRKOut(); !errors.Is(err, ErrStateViolation) {
		t.Fatalf("PRKOut after Close: %v", err)
	}
}

func TestRFC_MethodMismatchIsErrorMessage(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, _ *ResponderConfig) {
		ic.Method = MethodSigStat
	})
	m1, _ := ini.CreateMessage1()
	_, err := res.ProcessMessage1(m1)
	var em *ErrorMessage
	if !errors.As(err, &em) || em.Code != ErrCodeUnspecified || !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("err = %v", err)
	}
	wire, _ := em.MarshalCBOR()
	if _, err := ini.ProcessMessage2(wire); !errors.As(err, &em) {
		t.Fatalf("Initiator on error message: %v", err)
	}
}

func TestRFC_OffCurveP256Rejected(t *testing.T) {
	s, _ := lookupSuite(Suite2)
	// About half of all x values are not the x-coordinate of a P-256
	// point; those must be rejected, the rest decode.
	var rejected, accepted int
	for i := range 64 {
		x := make([]byte, 32)
		x[31] = byte(i)
		if _, err := s.decodePublic(x); err != nil {
			if !errors.Is(err, ErrMessageFormat) {
				t.Fatalf("x=%d: %v", i, err)
			}
			rejected++
		} else {
			accepted++
		}
	}
	if rejected == 0 || accepted == 0 {
		t.Fatalf("rejected %d, accepted %d of 64 x values", rejected, accepted)
	}
	if _, err := s.decodePublic(bytes.Repeat([]byte{0xff}, 32)); !errors.Is(err, ErrMessageFormat) {
		t.Fatalf("x>=p: %v", err)
	}
}

func TestRFC_ConnectionIDEncoding(t *testing.T) {
	for _, tc := range []struct {
		raw  []byte
		wire string
	}{
		{[]byte{0x2d}, "2d"},     // int -14
		{[]byte{0x0e}, "0e"},     // int 14
		{[]byte{0x18}, "4118"},   // not a one-byte int: bstr
		{[]byte{}, "40"},         // empty bstr
		{[]byte{1, 2}, "420102"}, // multi-byte bstr
	} {
		got := encodeCID(tc.raw)
		if hexs := bytesHex(got); hexs != tc.wire {
			t.Errorf("encodeCID(%x) = %s, want %s", tc.raw, hexs, tc.wire)
		}
	}
	for n := int8(-24); n <= 23; n++ {
		c, err := ConnectionIDFromInt(n)
		if err != nil || len(c) != 1 || !isOneByteInt(c[0]) {
			t.Fatalf("ConnectionIDFromInt(%d) = %x, %v", n, c, err)
		}
	}
	if _, err := ConnectionIDFromInt(24); err == nil {
		t.Fatal("ConnectionIDFromInt(24): want error")
	}
}

func bytesHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestRFC_RetrySuites(t *testing.T) {
	got, err := RetrySuites([]CipherSuite{Suite6, Suite2, Suite0}, &ErrorMessage{Code: ErrCodeWrongSelectedSuite, SuitesR: []CipherSuite{Suite0, Suite2}})
	if err != nil || len(got) != 2 || got[0] != Suite6 || got[1] != Suite2 {
		t.Fatalf("RetrySuites = %v, %v", got, err)
	}
	if _, err := RetrySuites([]CipherSuite{Suite6}, &ErrorMessage{Code: ErrCodeWrongSelectedSuite, SuitesR: []CipherSuite{Suite2}}); !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("no common suite: %v", err)
	}
}

// Every implemented suite completes a handshake (signature methods with
// suite-appropriate keys are covered by the traces and v0.2 tests; this
// covers static DH on each curve).
func TestRFC_StaticDHAllSuites(t *testing.T) {
	for _, id := range []CipherSuite{Suite0, Suite1, Suite2, Suite3, Suite4, Suite5, Suite6, Suite24} {
		s, _ := lookupSuite(id)
		iDH, _ := s.curve.GenerateKey(rand.Reader)
		rDH, _ := s.curve.GenerateKey(rand.Reader)
		ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{id}, Method: MethodStatStat, DHKey: iDH, PeerPublic: rDH.PublicKey(), ConnectionID: []byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{id}, Method: MethodStatStat, DHKey: rDH, PeerPublic: iDH.PublicKey(), ConnectionID: []byte{2}})
		if err != nil {
			t.Fatal(err)
		}
		m1, err := ini.CreateMessage1()
		if err != nil {
			t.Fatalf("suite %d: %v", id, err)
		}
		m2, err := res.ProcessMessage1(m1)
		if err != nil {
			t.Fatalf("suite %d: %v", id, err)
		}
		m3, err := ini.ProcessMessage2(m2)
		if err != nil {
			t.Fatalf("suite %d: %v", id, err)
		}
		if err := res.ProcessMessage3(m3); err != nil {
			t.Fatalf("suite %d: %v", id, err)
		}
		a, _ := ini.ExportOSCORE()
		b, _ := res.ExportOSCORE()
		if !bytes.Equal(a.MasterSecret, b.MasterSecret) || len(a.MasterSecret) != s.appKey {
			t.Fatalf("suite %d: OSCORE master secret mismatch", id)
		}
	}
}
