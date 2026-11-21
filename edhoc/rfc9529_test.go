// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jahkeup/corecbor"
)

// rfc9529 holds the labeled values of one RFC 9529 trace, in order.
type rfc9529 struct {
	labels []string
	values [][]byte
}

var (
	traceLabel = regexp.MustCompile(`^   (\S.*?)\s*\((\d+) bytes?\)\s*$`)
	traceHex   = regexp.MustCompile(`^   ([0-9a-f]{2}( [0-9a-f]{2})*)\s*$`)
	traceSect  = regexp.MustCompile(`^(\d)\.\s`)
)

// loadTrace parses section sec ("2" or "3") of the vendored RFC 9529.
// Each value is the hex block after a "<label> (<n> bytes)" line, read
// until n bytes are collected, which also skips page breaks.
func loadTrace(t *testing.T, sec string) *rfc9529 {
	t.Helper()
	data, err := os.ReadFile("../engineering-docs/rfcs/rfc9529.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n")
	tr := &rfc9529{}
	cur := ""
	for i := 0; i < len(lines); i++ {
		if m := traceSect.FindStringSubmatch(lines[i]); m != nil {
			cur = m[1]
		}
		if cur != sec {
			continue
		}
		m := traceLabel.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		var v []byte
		for j := i + 1; j < len(lines) && len(v) < n; j++ {
			hm := traceHex.FindStringSubmatch(lines[j])
			if hm == nil {
				if strings.HasPrefix(lines[j], "   ") && !strings.HasPrefix(strings.TrimSpace(lines[j]), "RFC") {
					break
				}
				continue
			}
			b, err := hex.DecodeString(strings.ReplaceAll(hm[1], " ", ""))
			if err != nil {
				t.Fatal(err)
			}
			v = append(v, b...)
			i = j
		}
		if len(v) != n {
			t.Fatalf("trace %s: %q: got %d bytes, want %d", sec, m[1], len(v), n)
		}
		tr.labels = append(tr.labels, m[1])
		tr.values = append(tr.values, v)
	}
	if len(tr.labels) == 0 {
		t.Fatalf("trace %s: no values parsed", sec)
	}
	return tr
}

// get returns the occurrence-th value with this label (-1: the last).
func (tr *rfc9529) get(t *testing.T, label string, occurrence int) []byte {
	t.Helper()
	var hits [][]byte
	for i, l := range tr.labels {
		if l == label {
			hits = append(hits, tr.values[i])
		}
	}
	if len(hits) == 0 {
		t.Fatalf("trace has no %q", label)
	}
	if occurrence < 0 {
		return hits[len(hits)-1]
	}
	return hits[occurrence]
}

type recorder map[string][]byte

func (r recorder) hook(name string, v []byte) { r[name] = bytes.Clone(v) }

// check compares the values recorded under name with the trace's label.
func check(t *testing.T, tr *rfc9529, rec recorder, name, label string) {
	t.Helper()
	got, ok := rec[name]
	if !ok {
		t.Errorf("%s: not recorded", name)
		return
	}
	if want := tr.get(t, label, -1); !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %x\nwant %x", name, got, want)
	}
}

func eq(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %x\nwant %x", what, got, want)
	}
}

func parseIDCredItem(t *testing.T, b []byte) IDCred {
	t.Helper()
	v, err := corecbor.NewDecoder(corecbor.WithoutInternalArena()).Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseIDCred(v, b)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The values every trace checks, by recorder name and RFC 9529 label.
var commonChecks = [][2]string{
	{"TH_2", "TH_2 (Raw Value)"},
	{"G_XY", "G_XY (Raw Value) (ECDH shared secret)"},
	{"PRK_2e", "PRK_2e (Raw Value)"},
	{"PRK_3e2m", "PRK_3e2m (Raw Value)"},
	{"context_2", "context_2 (CBOR Sequence)"},
	{"MAC_2", "MAC_2 (Raw Value)"},
	{"Signature_or_MAC_2", "Signature_or_MAC_2 (Raw Value)"},
	{"PLAINTEXT_2", "PLAINTEXT_2 (CBOR Sequence)"},
	{"KEYSTREAM_2", "KEYSTREAM_2 (Raw Value)"},
	{"CIPHERTEXT_2", "CIPHERTEXT_2 (Raw Value)"},
	{"TH_3", "TH_3 (Raw Value)"},
	{"PRK_4e3m", "PRK_4e3m (Raw Value)"},
	{"context_3", "context_3 (CBOR Sequence)"},
	{"MAC_3", "MAC_3 (Raw Value)"},
	{"Signature_or_MAC_3", "Signature_or_MAC_3 (Raw Value)"},
	{"PLAINTEXT_3", "PLAINTEXT_3 (CBOR Sequence)"},
	{"A_3", "A_3 (CBOR Data Item)"},
	{"K_3", "K_3 (Raw Value)"},
	{"IV_3", "IV_3 (Raw Value)"},
	{"CIPHERTEXT_3", "CIPHERTEXT_3 (Raw Value)"},
	{"TH_4", "TH_4 (Raw Value)"},
	{"PRK_out", "PRK_out (Raw Value)"},
	{"PRK_exporter", "PRK_exporter (Raw Value)"},
	{"A_4", "A_4 (CBOR Data Item)"},
	{"K_4", "K_4 (Raw Value)"},
	{"IV_4", "IV_4 (Raw Value)"},
}

// finish runs message_3/message_4 and the outputs common to both
// traces, then checks them.
func finish(t *testing.T, tr *rfc9529, ini *Initiator, res *Responder, msg2 []byte, ri, rr recorder) {
	t.Helper()
	eq(t, "message_2", msg2, tr.get(t, "message_2 (CBOR Sequence)", -1))
	msg3, err := ini.ProcessMessage2(msg2)
	if err != nil {
		t.Fatalf("ProcessMessage2: %v", err)
	}
	eq(t, "message_3", msg3, tr.get(t, "message_3 (CBOR Sequence)", -1))
	if err := res.ProcessMessage3(msg3); err != nil {
		t.Fatalf("ProcessMessage3: %v", err)
	}
	msg4, err := res.CreateMessage4()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "message_4", msg4, tr.get(t, "message_4 (CBOR Sequence)", -1))
	if err := ini.ProcessMessage4(msg4); err != nil {
		t.Fatalf("ProcessMessage4: %v", err)
	}

	// Responder-side values come from the responder; the initiator
	// computes message_3's.
	merged := recorder{}
	for k, v := range rr {
		merged[k] = v
	}
	for _, k := range []string{"PRK_4e3m", "context_3", "MAC_3", "Signature_or_MAC_3", "PLAINTEXT_3", "A_3", "K_3", "IV_3", "CIPHERTEXT_3", "TH_4", "PRK_out", "PRK_exporter"} {
		if v, ok := ri[k]; ok {
			merged[k] = v
		}
	}
	for _, c := range commonChecks {
		check(t, tr, merged, c[0], c[1])
	}
	// Both sides must agree on the handshake outputs.
	for _, k := range []string{"TH_2", "TH_3", "TH_4", "PRK_out", "PRK_exporter"} {
		eq(t, "initiator/responder "+k, ri[k], rr[k])
	}

	io, err := ini.ExportOSCORE()
	if err != nil {
		t.Fatal(err)
	}
	ro, err := res.ExportOSCORE()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "OSCORE Master Secret", io.MasterSecret, tr.get(t, "OSCORE Master Secret (Raw Value)", -1))
	eq(t, "OSCORE Master Salt", io.MasterSalt, tr.get(t, "OSCORE Master Salt (Raw Value)", -1))
	eq(t, "responder Master Secret", ro.MasterSecret, io.MasterSecret)
	eq(t, "Client's OSCORE Sender ID", io.SenderID, tr.get(t, "Client's OSCORE Sender ID (Raw Value)", -1))
	eq(t, "Server's OSCORE Sender ID", ro.SenderID, tr.get(t, "Server's OSCORE Sender ID (Raw Value)", -1))
	eq(t, "client Recipient ID", io.RecipientID, ro.SenderID)

	ctx := tr.get(t, "context for KeyUpdate (Raw Value)", -1)
	if err := ini.KeyUpdate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := res.KeyUpdate(ctx); err != nil {
		t.Fatal(err)
	}
	po, _ := ini.PRKOut()
	eq(t, "PRK_out after KeyUpdate", po, tr.get(t, "PRK_out after KeyUpdate (Raw Value)", -1))
	io2, _ := ini.ExportOSCORE()
	eq(t, "OSCORE Master Secret after KeyUpdate", io2.MasterSecret, tr.get(t, "OSCORE Master Secret after KeyUpdate (Raw Value)", -1))
	eq(t, "OSCORE Master Salt after KeyUpdate", io2.MasterSalt, tr.get(t, "OSCORE Master Salt after KeyUpdate (Raw Value)", -1))
	ro2, _ := res.ExportOSCORE()
	eq(t, "responder Master Secret after KeyUpdate", ro2.MasterSecret, io2.MasterSecret)
}

// TestRFC9529Trace1 is RFC 9529 §2: method 0 (signatures), suite 0,
// X.509 credentials identified by x5t.
func TestRFC9529Trace1(t *testing.T) {
	tr := loadTrace(t, "2")
	g := func(l string) []byte { return tr.get(t, l, -1) }

	credR := &Credential{
		Raw:       g("CRED_R (CBOR Data Item)"),
		IDCred:    parseIDCredItem(t, g("ID_CRED_R (CBOR Data Item)")),
		PublicKey: ed25519.PublicKey(g("PK_R (Raw Value)")),
	}
	credI := &Credential{
		Raw:       g("CRED_I (CBOR Data Item)"),
		IDCred:    parseIDCredItem(t, g("ID_CRED_I (CBOR Data Item)")),
		PublicKey: ed25519.PublicKey(g("PK_I (Raw Value)")),
	}
	ri, rr := recorder{}, recorder{}
	ini, err := NewInitiator(InitiatorConfig{
		Suites:         []CipherSuite{Suite0},
		Method:         MethodSigSig,
		PrivateKey:     ed25519.NewKeyFromSeed(g("SK_I (Raw Value)")),
		Credential:     credI,
		PeerCredential: credR,
		ConnectionID:   g("C_I (Raw Value)"),
		Rand:           bytes.NewReader(g("X (Raw Value)")),
	})
	if err != nil {
		t.Fatal(err)
	}
	ini.s.trace = ri.hook
	res, err := NewResponder(ResponderConfig{
		Suites:         []CipherSuite{Suite0},
		Method:         MethodSigSig,
		PrivateKey:     ed25519.NewKeyFromSeed(g("SK_R (Raw Value)")),
		Credential:     credR,
		PeerCredential: credI,
		ConnectionID:   g("C_R (Raw Value)"),
		Rand:           bytes.NewReader(g("Y (Raw Value)")),
	})
	if err != nil {
		t.Fatal(err)
	}
	res.s.trace = rr.hook

	msg1, err := ini.CreateMessage1()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "message_1", msg1, g("message_1 (CBOR Sequence)"))
	msg2, err := res.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	finish(t, tr, ini, res, msg2, ri, rr)
}

// TestRFC9529Trace2 is RFC 9529 §3: method 3 (static DH), a suite
// negotiation error, then suite 2 with CCS credentials identified by
// kid.
func TestRFC9529Trace2(t *testing.T) {
	tr := loadTrace(t, "3")
	g := func(l string, occ int) []byte { return tr.get(t, l, occ) }

	skI, err := ecdh.P256().NewPrivateKey(g("SK_I (Raw Value)", -1))
	if err != nil {
		t.Fatal(err)
	}
	skR, err := ecdh.P256().NewPrivateKey(g("SK_R (Raw Value)", -1))
	if err != nil {
		t.Fatal(err)
	}
	credR := &Credential{
		Raw:       g("CRED_R (CBOR Data Item)", -1),
		IDCred:    parseIDCredItem(t, g("ID_CRED_R (CBOR Data Item)", -1)),
		PublicKey: skR.PublicKey(),
	}
	credI := &Credential{
		Raw:       g("CRED_I (CBOR Data Item)", -1),
		IDCred:    parseIDCredItem(t, g("ID_CRED_I (CBOR Data Item)", -1)),
		PublicKey: skI.PublicKey(),
	}
	respCfg := ResponderConfig{
		Suites:         []CipherSuite{Suite2},
		Method:         MethodStatStat,
		DHKey:          skR,
		Credential:     credR,
		PeerCredential: credI,
		ConnectionID:   g("C_R (raw value)", -1),
		Rand:           bytes.NewReader(g("Y (Raw Value)", -1)),
	}
	iniCfg := func(suites []CipherSuite, x, ci []byte) InitiatorConfig {
		return InitiatorConfig{
			Suites:         suites,
			Method:         MethodStatStat,
			DHKey:          skI,
			Credential:     credI,
			PeerCredential: credR,
			ConnectionID:   ci,
			Rand:           bytes.NewReader(x),
		}
	}

	// First attempt: suite 6, which the Responder doesn't support.
	ini1, err := NewInitiator(iniCfg([]CipherSuite{Suite6}, g("X (Raw Value)", 0), g("C_I (Raw Value)", 0)))
	if err != nil {
		t.Fatal(err)
	}
	msg1a, err := ini1.CreateMessage1()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 9529 §3.1's first message_1 carries a P-256 G_X although its
	// selected suite 6 uses X25519 (the message is rejected before G_X
	// is used). Compare it with G_X masked, and give the Responder the
	// RFC's own bytes.
	rfcMsg1a := g("message_1 (CBOR Sequence)", 0)
	if len(msg1a) != len(rfcMsg1a) {
		t.Fatalf("message_1 (first): length %d, want %d", len(msg1a), len(rfcMsg1a))
	}
	eq(t, "message_1 (first) without G_X", append(bytes.Clone(msg1a[:4]), msg1a[36:]...), append(bytes.Clone(rfcMsg1a[:4]), rfcMsg1a[36:]...))
	res1, err := NewResponder(respCfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = res1.ProcessMessage1(rfcMsg1a)
	var em *ErrorMessage
	if !errors.As(err, &em) || !errors.Is(err, ErrPeerError) {
		t.Fatalf("ProcessMessage1(suite 6): err = %v, want *ErrorMessage", err)
	}
	wire, err := em.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "error", wire, g("error (CBOR Sequence)", 0))
	if _, err := ini1.ProcessMessage2(wire); !errors.As(err, &em) || em.Code != ErrCodeWrongSelectedSuite {
		t.Fatalf("Initiator on error message: %v", err)
	}
	suites, err := RetrySuites([]CipherSuite{Suite6, Suite2}, em)
	if err != nil {
		t.Fatal(err)
	}

	// Second attempt with SUITES_I [6, 2].
	ri, rr := recorder{}, recorder{}
	ini, err := NewInitiator(iniCfg(suites, g("X (Raw Value)", 1), g("C_I (Raw Value)", 1)))
	if err != nil {
		t.Fatal(err)
	}
	ini.s.trace = ri.hook
	msg1, err := ini.CreateMessage1()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "message_1 (second)", msg1, g("message_1 (CBOR Sequence)", 1))
	respCfg.Rand = bytes.NewReader(g("Y (Raw Value)", -1))
	res, err := NewResponder(respCfg)
	if err != nil {
		t.Fatal(err)
	}
	res.s.trace = rr.hook
	msg2, err := res.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	finish(t, tr, ini, res, msg2, ri, rr)
}
