// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"strings"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/edhoc"
	g "github.com/jahkeup/corecbor/internal/goldentest"
)

// TestGoldenV022 enforces proposal 034 for the edhoc module. EDHOC
// output is randomized (ephemeral keys, ECDSA), so vectors record only
// deterministic properties: message structure with byte strings reduced
// to their lengths, outcomes, error sentinels, and connection-ID mapping.
func TestGoldenV022(t *testing.T) {
	g.Check(t, "testdata/golden/v0.2.2/edhoc.json", edhocGoldenCases(), goldenChanges)
}

var edhocSentinels = []g.Sentinel{
	{Name: "ErrAuthentication", Err: edhoc.ErrAuthentication},
	{Name: "ErrMessageFormat", Err: edhoc.ErrMessageFormat},
	{Name: "ErrStateViolation", Err: edhoc.ErrStateViolation},
	{Name: "ErrUnsupportedSuite", Err: edhoc.ErrUnsupportedSuite},
}

func okOf(err error) string { return g.OK(err, edhocSentinels) }

type party struct {
	priv crypto.Signer
	pub  crypto.PublicKey
}

func edParty(b byte) party {
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
	return party{k, k.Public()}
}

func p256Party(b byte) party {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{b}, 32))
	if err != nil {
		panic(err)
	}
	return party{k, &k.PublicKey}
}

// shape renders a CBOR sequence with byte strings replaced by their
// length, so randomized content doesn't leak into the vector.
func shape(data []byte) string {
	seq, err := corecbor.DecodeSequence(data)
	if err != nil {
		return "undecodable(" + g.Err(err, nil) + ")"
	}
	parts := make([]string, len(seq))
	for i, v := range seq {
		parts[i] = shapeValue(v)
	}
	return strings.Join(parts, ", ")
}

func shapeValue(v corecbor.Value) string {
	switch v.Kind {
	case corecbor.KindBytes:
		return fmt.Sprintf("bstr(%d)", len(v.BytesVal()))
	case corecbor.KindText:
		return fmt.Sprintf("tstr(%d)", len(v.TextVal()))
	case corecbor.KindArray:
		items := v.Array()
		parts := make([]string, len(items))
		for i, it := range items {
			parts[i] = shapeValue(it)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case corecbor.KindMap:
		return fmt.Sprintf("map(%d)", len(v.Map()))
	default:
		return corecbor.DiagnosticValue(v)
	}
}

type handshake struct {
	init *edhoc.Initiator
	resp *edhoc.Responder
	msgs [4][]byte
	err  error
	step string
}

func runHandshake(suite edhoc.CipherSuite, i, r party, iPeer, rPeer crypto.PublicKey) *handshake {
	h := &handshake{}
	fail := func(step string, err error) *handshake { h.step, h.err = step, err; return h }
	var err error
	h.init, err = edhoc.NewInitiator(edhoc.InitiatorConfig{
		Suites: []edhoc.CipherSuite{suite}, PrivateKey: i.priv, PeerPublic: iPeer, ConnectionID: []byte{0x0a},
	})
	if err != nil {
		return fail("new-initiator", err)
	}
	h.resp, err = edhoc.NewResponder(edhoc.ResponderConfig{
		Suites: []edhoc.CipherSuite{suite}, PrivateKey: r.priv, PeerPublic: rPeer, ConnectionID: []byte{0x0b},
	})
	if err != nil {
		return fail("new-responder", err)
	}
	if h.msgs[0], err = h.init.CreateMessage1(); err != nil {
		return fail("msg1", err)
	}
	if h.msgs[1], err = h.resp.ProcessMessage1(h.msgs[0]); err != nil {
		return fail("msg2", err)
	}
	if h.msgs[2], err = h.init.ProcessMessage2(h.msgs[1]); err != nil {
		return fail("process-msg2", err)
	}
	if err = h.resp.ProcessMessage3(h.msgs[2]); err != nil {
		return fail("process-msg3", err)
	}
	if h.msgs[3], err = h.resp.CreateMessage4(); err != nil {
		return fail("msg4", err)
	}
	if err = h.init.ProcessMessage4(h.msgs[3]); err != nil {
		return fail("process-msg4", err)
	}
	return h
}

func (h *handshake) outcome() string {
	if h.err != nil {
		return h.step + ":" + g.Err(h.err, edhocSentinels)
	}
	return "ok"
}

func edhocGoldenCases() []g.Case {
	var cases []g.Case
	add := func(id string, run func() string) { cases = append(cases, g.Case{ID: id, Run: run}) }

	suites := []struct {
		name  string
		suite edhoc.CipherSuite
		mk    func(byte) party
	}{
		{"suite0", edhoc.Suite0, edParty},
		{"suite2", edhoc.Suite2, p256Party},
	}
	for _, s := range suites {
		i, r := s.mk(1), s.mk(2)
		hs := func() *handshake { return runHandshake(s.suite, i, r, r.pub, i.pub) }
		add("edhoc/handshake/"+s.name+"/outcome", func() string { return hs().outcome() })
		for n := range 4 {
			add(fmt.Sprintf("edhoc/handshake/%s/message%d-shape", s.name, n+1), func() string {
				h := hs()
				if h.err != nil {
					return h.outcome()
				}
				return "ok:" + shape(h.msgs[n])
			})
		}
		add("edhoc/handshake/"+s.name+"/oscore-context", func() string {
			h := hs()
			if h.err != nil {
				return h.outcome()
			}
			ic, err := h.init.ExportOSCORE()
			if err != nil {
				return okOf(err)
			}
			rc, err := h.resp.ExportOSCORE()
			if err != nil {
				return okOf(err)
			}
			return fmt.Sprintf("ok:init{sender=%x recipient=%x secret=%d salt=%d} resp{sender=%x recipient=%x} secrets-match=%v salts-match=%v",
				ic.SenderID, ic.RecipientID, len(ic.MasterSecret), len(ic.MasterSalt), rc.SenderID, rc.RecipientID,
				bytes.Equal(ic.MasterSecret, rc.MasterSecret), bytes.Equal(ic.MasterSalt, rc.MasterSalt))
		})
		add("edhoc/handshake/"+s.name+"/exporter", func() string {
			h := hs()
			if h.err != nil {
				return h.outcome()
			}
			a, err := h.init.Export(0, nil, 16)
			if err != nil {
				return okOf(err)
			}
			b, err := h.resp.Export(0, nil, 16)
			if err != nil {
				return okOf(err)
			}
			c, err := h.init.Export(1, nil, 16)
			if err != nil {
				return okOf(err)
			}
			return fmt.Sprintf("ok:len=%d match=%v label-differs=%v", len(a), bytes.Equal(a, b), !bytes.Equal(a, c))
		})
		add("edhoc/handshake/"+s.name+"/wrong-peer-key", func() string {
			other := s.mk(3)
			return runHandshake(s.suite, i, r, other.pub, i.pub).outcome()
		})
		add("edhoc/handshake/"+s.name+"/tampered-message2", func() string {
			init, err := edhoc.NewInitiator(edhoc.InitiatorConfig{Suites: []edhoc.CipherSuite{s.suite}, PrivateKey: i.priv, PeerPublic: r.pub, ConnectionID: []byte{0x0a}})
			if err != nil {
				return okOf(err)
			}
			resp, err := edhoc.NewResponder(edhoc.ResponderConfig{Suites: []edhoc.CipherSuite{s.suite}, PrivateKey: r.priv, PeerPublic: i.pub, ConnectionID: []byte{0x0b}})
			if err != nil {
				return okOf(err)
			}
			m1, err := init.CreateMessage1()
			if err != nil {
				return okOf(err)
			}
			m2, err := resp.ProcessMessage1(m1)
			if err != nil {
				return okOf(err)
			}
			m2[len(m2)-1] ^= 0xff
			_, err = init.ProcessMessage2(m2)
			return okOf(err)
		})
	}

	ed1, ed2 := edParty(1), edParty(2)
	add("edhoc/config/initiator-no-suites", func() string {
		_, err := edhoc.NewInitiator(edhoc.InitiatorConfig{PrivateKey: ed1.priv, PeerPublic: ed2.pub})
		return okOf(err)
	})
	add("edhoc/config/initiator-unsupported-suite", func() string {
		_, err := edhoc.NewInitiator(edhoc.InitiatorConfig{Suites: []edhoc.CipherSuite{1}, PrivateKey: ed1.priv, PeerPublic: ed2.pub})
		return okOf(err)
	})
	add("edhoc/config/initiator-missing-keys", func() string {
		_, err := edhoc.NewInitiator(edhoc.InitiatorConfig{Suites: []edhoc.CipherSuite{edhoc.Suite0}})
		return okOf(err)
	})
	add("edhoc/config/responder-missing-keys", func() string {
		_, err := edhoc.NewResponder(edhoc.ResponderConfig{Suites: []edhoc.CipherSuite{edhoc.Suite0}})
		return okOf(err)
	})
	add("edhoc/config/responder-no-suites", func() string {
		_, err := edhoc.NewResponder(edhoc.ResponderConfig{PrivateKey: ed2.priv, PeerPublic: ed1.pub})
		return okOf(err)
	})

	newResp := func(suites ...edhoc.CipherSuite) *edhoc.Responder {
		r, err := edhoc.NewResponder(edhoc.ResponderConfig{Suites: suites, PrivateKey: ed2.priv, PeerPublic: ed1.pub, ConnectionID: []byte{0x0b}})
		if err != nil {
			panic(err)
		}
		return r
	}
	newInit := func() *edhoc.Initiator {
		i, err := edhoc.NewInitiator(edhoc.InitiatorConfig{Suites: []edhoc.CipherSuite{edhoc.Suite0}, PrivateKey: ed1.priv, PeerPublic: ed2.pub, ConnectionID: []byte{0x0a}})
		if err != nil {
			panic(err)
		}
		return i
	}
	for _, in := range []struct{ name, hex string }{
		{"empty", ""},
		{"garbage", "ff"},
		{"array", "8100"},
		{"truncated", "00"},
		{"method-1", "01005820" + strings.Repeat("00", 32) + "0a"},
		{"gx-short", "00004100" + "0a"},
		{"suite-unknown", "00055820" + strings.Repeat("09", 32) + "0a"},
		{"trailing-bytes", "00005820" + strings.Repeat("09", 32) + "0a" + "01"},
	} {
		add("edhoc/message1/"+in.name, func() string {
			_, err := newResp(edhoc.Suite0).ProcessMessage1(g.MustHex(in.hex))
			return okOf(err)
		})
	}
	add("edhoc/state/process-message2-before-message1", func() string {
		_, err := newInit().ProcessMessage2([]byte{0})
		return okOf(err)
	})
	add("edhoc/state/create-message1-twice", func() string {
		i := newInit()
		if _, err := i.CreateMessage1(); err != nil {
			return okOf(err)
		}
		_, err := i.CreateMessage1()
		return okOf(err)
	})
	add("edhoc/state/process-message4-before-complete", func() string { return okOf(newInit().ProcessMessage4([]byte{0})) })
	add("edhoc/state/initiator-export-before-complete", func() string {
		_, err := newInit().Export(0, nil, 16)
		return okOf(err)
	})
	add("edhoc/state/initiator-oscore-before-complete", func() string {
		_, err := newInit().ExportOSCORE()
		return okOf(err)
	})
	add("edhoc/state/responder-message3-before-message1", func() string {
		return okOf(newResp(edhoc.Suite0).ProcessMessage3([]byte{0}))
	})
	add("edhoc/state/responder-message4-before-complete", func() string {
		_, err := newResp(edhoc.Suite0).CreateMessage4()
		return okOf(err)
	})
	add("edhoc/state/responder-export-before-complete", func() string {
		_, err := newResp(edhoc.Suite0).Export(0, nil, 16)
		return okOf(err)
	})
	add("edhoc/state/process-message1-twice", func() string {
		r := newResp(edhoc.Suite0)
		m1, err := newInit().CreateMessage1()
		if err != nil {
			return okOf(err)
		}
		if _, err := r.ProcessMessage1(m1); err != nil {
			return okOf(err)
		}
		_, err = r.ProcessMessage1(m1)
		return okOf(err)
	})
	add("edhoc/negotiation/responder-lacks-suite", func() string {
		m1, err := newInit().CreateMessage1()
		if err != nil {
			return okOf(err)
		}
		_, err = newResp(edhoc.Suite2).ProcessMessage1(m1)
		return okOf(err)
	})
	add("edhoc/suites/constants", func() string { return fmt.Sprintf("ok:suite0=%d suite2=%d", edhoc.Suite0, edhoc.Suite2) })
	return cases
}
