// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

// Tests for the proposal 037 edhoc findings (E1–E20), each written to
// fail against the behavior the review recorded.

// E3: after Signature_or_MAC_2 fails to verify, the Initiator exposes
// neither the Responder's credential nor EAD_2.
func TestE3_NoPeerValuesAfterFailedMessage2(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, func(_ *InitiatorConfig, rc *ResponderConfig) {
		rc.EAD2 = []EADItem{{Label: 5, Value: []byte("x")}}
	})
	m1, _ := ini.CreateMessage1()
	m2, err := res.ProcessMessage1(m1)
	if err != nil {
		t.Fatal(err)
	}
	// PLAINTEXT_2 ends with Signature_or_MAC_2 then EAD_2 (05 41 78); flip
	// the signature's last byte so the credential resolves but the
	// signature fails.
	bad := bytes.Clone(m2)
	bad[len(bad)-4] ^= 1
	if _, err := ini.ProcessMessage2(bad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered signature: %v", err)
	}
	if c := ini.PeerCredential(); c != nil {
		t.Errorf("PeerCredential after failed verification = %+v, want nil", c)
	}
	if e := ini.PeerEAD(); e != nil {
		t.Errorf("PeerEAD after failed verification = %+v, want nil", e)
	}
}

// E3: after Signature_or_MAC_3 fails to verify, the Responder exposes
// neither the Initiator's credential nor EAD_3 (nor EAD_1).
func TestE3_NoPeerValuesAfterFailedMessage3(t *testing.T) {
	_, other := edPair(t)
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
		ic.EAD1 = []EADItem{{Label: 4}}
		ic.EAD3 = []EADItem{{Label: 6, Value: []byte("y")}}
		// The resolver accepts the CCS but binds it to another key, so
		// the credential resolves and the signature check fails.
		rc.Peers = resolverFunc(func(_ context.Context, id IDCred) (*Credential, error) {
			return &Credential{Raw: id.KCCS, IDCred: id, PublicKey: other}, nil
		})
	})
	m1, _ := ini.CreateMessage1()
	m2, err := res.ProcessMessage1(m1)
	if err != nil {
		t.Fatal(err)
	}
	m3, err := ini.ProcessMessage2(m2)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.ProcessMessage3(m3); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
	if c := res.PeerCredential(); c != nil {
		t.Errorf("PeerCredential after failed verification = %+v, want nil", c)
	}
	if e := res.PeerEAD(); e != nil {
		t.Errorf("PeerEAD after failed verification = %+v, want nil", e)
	}
}

// E2: a signing key is not used as a static DH key, on either side.
func TestE2_SigningKeyNotUsedForDH(t *testing.T) {
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Local: method 2 has the Initiator authenticate with static DH;
	// an ECDSA PrivateKey without DHKey is refused.
	_, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite2}, Method: MethodStatSig, PrivateKey: ik, PeerPublic: &rk.PublicKey, ConnectionID: []byte{1}})
	if !errors.Is(err, ErrStateViolation) || !strings.Contains(err.Error(), "DHKey") {
		t.Errorf("NewInitiator(method 2, ECDSA key only): %v, want ErrStateViolation naming DHKey", err)
	}
	_, err = NewResponder(ResponderConfig{Suites: []CipherSuite{Suite2}, Method: MethodSigStat, PrivateKey: rk, PeerPublic: &ik.PublicKey, ConnectionID: []byte{2}})
	if !errors.Is(err, ErrStateViolation) {
		t.Errorf("NewResponder(method 1, ECDSA key only): %v, want ErrStateViolation", err)
	}
	// With AnyMethod the method is known only from message_1.
	ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite2}, Method: MethodSigStat, PrivateKey: ik, PeerPublic: &rk.PublicKey, ConnectionID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite2}, AnyMethod: true, PrivateKey: rk, PeerPublic: &ik.PublicKey, ConnectionID: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	m1, _ := ini.CreateMessage1()
	if _, err := res.ProcessMessage1(m1); !errors.Is(err, ErrStateViolation) {
		t.Errorf("Responder static DH with an ECDSA key only: %v, want ErrStateViolation", err)
	}
}

// E2: a peer credential whose COSE_Key names a signature algorithm is
// not accepted for static DH, and one naming key agreement is not
// accepted for signatures.
func TestE2_PeerKeyUseFromCOSEKey(t *testing.T) {
	run := func(method Method, ownToo bool, alg cose.Algorithm, ops ...cose.KeyOp) error {
		iDH, _ := ecdh.P256().GenerateKey(rand.Reader)
		iSig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		rSig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		var iPub crypto.PublicKey = iDH.PublicKey()
		if method.initiatorSigns() {
			iPub = &iSig.PublicKey
		}
		k, err := cose.NewKeyFromPublic(iPub)
		if err != nil {
			t.Fatal(err)
		}
		if alg != 0 {
			k.SetAlgorithm(alg)
		}
		if ops != nil {
			k.SetOps(ops...)
		}
		kb, _ := k.MarshalCBOR()
		kv, _ := corecbor.NewDecoder(seqDecOpts...).Decode(kb)
		ccs := item(cbor.MakeMap(cbor.MapEntry{Key: cbor.Uint(ccsClaimCnf), Value: cbor.MakeMap(cbor.MapEntry{Key: cbor.Uint(cnfCOSEKey), Value: kv})}))
		ic := InitiatorConfig{Suites: []CipherSuite{Suite2}, Method: method, PrivateKey: iSig, DHKey: iDH, PeerPublic: &rSig.PublicKey, ConnectionID: []byte{1}}
		if ownToo {
			ic.Credential = &Credential{Raw: ccs}
		}
		ini, err := NewInitiator(ic)
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite2}, Method: method, PrivateKey: rSig, ConnectionID: []byte{2},
			Peers: resolverFunc(func(context.Context, IDCred) (*Credential, error) {
				return &Credential{Raw: ccs, PublicKey: iPub}, nil
			})})
		if err != nil {
			t.Fatal(err)
		}
		return handshake(t, ini, res)
	}
	for _, c := range []struct {
		name   string
		method Method
		alg    cose.Algorithm
		ops    []cose.KeyOp
	}{
		{"ES256 key for static DH", MethodStatSig, cose.AlgES256, nil},
		{"verify-only key for static DH", MethodStatSig, 0, []cose.KeyOp{cose.KeyOpVerify}},
		{"ECDH-ES key for signatures", MethodSigSig, cose.AlgECDH_ES_HKDF_256, nil},
		{"deriveBits-only key for signatures", MethodSigSig, 0, []cose.KeyOp{cose.KeyOpDeriveBits}},
	} {
		err := run(c.method, false, c.alg, c.ops...)
		if !errors.Is(err, ErrAuthentication) || !strings.Contains(err.Error(), "not usable") {
			t.Errorf("peer %s: %v, want ErrAuthentication naming the key use", c.name, err)
		}
		// The same credential as this party's own is refused locally.
		err = run(c.method, true, c.alg, c.ops...)
		if !errors.Is(err, ErrStateViolation) || !strings.Contains(err.Error(), "not usable") {
			t.Errorf("own %s: %v, want ErrStateViolation naming the key use", c.name, err)
		}
	}
	// Keys whose alg or key_ops match the method complete.
	if err := run(MethodStatSig, true, cose.AlgECDH_ES_HKDF_256); err != nil {
		t.Errorf("ECDH-ES key for static DH: %v", err)
	}
	if err := run(MethodSigSig, true, cose.AlgES256, cose.KeyOpVerify); err != nil {
		t.Errorf("ES256 key for signatures: %v", err)
	}
}

// E4: X509Resolver without an identity check fails closed unless the
// caller opts into accepting any leaf under Roots.
func TestE4_X509IdentityCheckRequired(t *testing.T) {
	pki := newTestPKI(t)
	_, chain := pki.leaf(t, "peer")
	p := X509Policy{Roots: pki.roots, CurrentTime: pki.now}
	_, err := X509Resolver(p).ResolveCredential(context.Background(), IDCred{X5Chain: chain})
	if !errors.Is(err, ErrAuthentication) || !strings.Contains(err.Error(), "VerifyPeer") {
		t.Errorf("no VerifyPeer: %v, want ErrAuthentication naming VerifyPeer", err)
	}
	p.AllowAnyPeerUnderRoots = true
	if _, err := X509Resolver(p).ResolveCredential(context.Background(), IDCred{X5Chain: chain}); err != nil {
		t.Errorf("AllowAnyPeerUnderRoots: %v", err)
	}
	p.AllowAnyPeerUnderRoots = false
	p.VerifyPeer = func(c *x509.Certificate) error { return nil }
	if _, err := X509Resolver(p).ResolveCredential(context.Background(), IDCred{X5Chain: chain}); err != nil {
		t.Errorf("VerifyPeer: %v", err)
	}
}

// E4: the certificate's keyUsage must match the method: a
// keyAgreement-only certificate does not authenticate a signature.
func TestE4_X509KeyUsageMatchesMethod(t *testing.T) {
	run := func(usage x509.KeyUsage) error {
		pki := newTestPKI(t)
		pki.leafUsage = usage
		iKey, iChain := pki.leaf(t, "initiator")
		rKey, rChain := pki.leaf(t, "responder")
		pki.leafUsage = 0
		iCred, _ := X509Credential(iChain, false)
		rCred, _ := X509Credential(rChain, false)
		// The Responder's own credential is fine; the Initiator's is
		// checked by the Responder as a peer and by itself as its own.
		ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iKey, ConnectionID: []byte{1}, Credential: iCred, Peers: X509Resolver(pki.policy())})
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rKey, ConnectionID: []byte{2}, Credential: rCred, Peers: X509Resolver(pki.policy())})
		if err != nil {
			t.Fatal(err)
		}
		return handshake(t, ini, res)
	}
	if err := run(x509.KeyUsageDigitalSignature); err != nil {
		t.Errorf("digitalSignature: %v", err)
	}
	if err := run(x509.KeyUsageKeyAgreement); err == nil || !strings.Contains(err.Error(), "keyUsage") {
		t.Errorf("keyAgreement-only certificates for signatures: %v, want a keyUsage error", err)
	}
	// A P-curve key may do either; the keyUsage decides.
	pki := newTestPKI(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, c := range []struct {
		usage      x509.KeyUsage
		sign, stat bool
	}{
		{x509.KeyUsageKeyAgreement, false, true},
		{x509.KeyUsageDigitalSignature, true, false},
		{x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, true, true},
		{x509.KeyUsageDataEncipherment, false, false},
	} {
		pki.leafUsage = c.usage
		leaf := pki.cert(t, "peer", &k.PublicKey, pki.inter, pki.inKey, false, pki.now.Add(-time.Minute), pki.now.Add(time.Minute))
		cred, err := X509Credential([][]byte{leaf.Raw}, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkUse(cred, true); (err == nil) != c.sign {
			t.Errorf("keyUsage %b for signatures: %v", c.usage, err)
		}
		if err := checkUse(cred, false); (err == nil) != c.stat {
			t.Errorf("keyUsage %b for static DH: %v", c.usage, err)
		}
	}
}

// E5: the default allocator never hands one identifier to two live
// endpoints, and frees it on Close.
func TestE5_DefaultAllocatorAvoidsLiveSessions(t *testing.T) {
	var live []*Initiator
	seen := map[string]bool{}
	for range 64 { // more than the 48 one-byte integer identifiers
		ini, _ := pair(t, nil, []byte{2}, nil)
		if _, err := ini.CreateMessage1(); err != nil {
			t.Fatal(err)
		}
		id := string(ini.ConnectionID())
		if seen[id] {
			t.Fatalf("C_I %x handed out twice to live sessions", id)
		}
		seen[id] = true
		live = append(live, ini)
	}
	for _, ini := range live {
		ini.Close()
	}

	// Close releases: with a reader that always draws 0x36, a second
	// live session gets something else, and a session started after the
	// first closes gets 0x36 again.
	draw := func() []byte { return bytes.Repeat([]byte{46}, 1024) } // 46 maps to 0x36
	start := func() *Initiator {
		ini, _ := pair(t, nil, []byte{2}, func(ic *InitiatorConfig, _ *ResponderConfig) { ic.Rand = bytes.NewReader(draw()) })
		// Rand also supplies the ephemeral key: give it room.
		if _, err := ini.CreateMessage1(); err != nil {
			t.Fatal(err)
		}
		return ini
	}
	a := start()
	if got := a.ConnectionID(); !bytes.Equal(got, []byte{0x36}) {
		t.Fatalf("first C_I = %x, want 36", got)
	}
	b := start()
	if bytes.Equal(b.ConnectionID(), a.ConnectionID()) {
		t.Fatal("second live session reused C_I")
	}
	a.Close()
	c := start()
	if got := c.ConnectionID(); !bytes.Equal(got, []byte{0x36}) {
		t.Errorf("C_I after Close = %x, want 36 again", got)
	}
	b.Close()
	c.Close()
}

// E5: a caller-supplied allocator chooses the identifier, sees the
// peer's, and may not return it.
func TestE5_AllocatorHook(t *testing.T) {
	var sawPeer ConnectionID
	ini, res := pair(t, []byte{7}, nil, func(_ *InitiatorConfig, rc *ResponderConfig) {
		rc.AllocateConnectionID = func(peer ConnectionID) (ConnectionID, error) {
			sawPeer = peer
			return ConnectionID{0xab, 0xcd}, nil
		}
	})
	m1, _ := ini.CreateMessage1()
	if _, err := res.ProcessMessage1(m1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sawPeer, []byte{7}) || !bytes.Equal(res.ConnectionID(), []byte{0xab, 0xcd}) {
		t.Fatalf("allocator saw %x, C_R = %x", sawPeer, res.ConnectionID())
	}

	ini, res = pair(t, []byte{7}, nil, func(_ *InitiatorConfig, rc *ResponderConfig) {
		rc.AllocateConnectionID = func(peer ConnectionID) (ConnectionID, error) { return peer, nil }
	})
	m1, _ = ini.CreateMessage1()
	if _, err := res.ProcessMessage1(m1); !errors.Is(err, ErrConnectionIDCollision) {
		t.Errorf("allocator returning C_I: %v, want ErrConnectionIDCollision", err)
	}
	boom := errors.New("table full")
	ini, _ = pair(t, nil, []byte{2}, func(ic *InitiatorConfig, _ *ResponderConfig) {
		ic.AllocateConnectionID = func(ConnectionID) (ConnectionID, error) { return nil, boom }
	})
	if _, err := ini.CreateMessage1(); !errors.Is(err, boom) || !errors.Is(err, ErrStateViolation) {
		t.Errorf("allocator error: %v", err)
	}
}

// E19: zero-value endpoints return ErrStateViolation instead of
// panicking.
func TestE19_ZeroValueEndpoints(t *testing.T) {
	check := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrStateViolation) {
			t.Errorf("%s: %v, want ErrStateViolation", name, err)
		}
	}
	for _, i := range []*Initiator{{}, nil} {
		_, err := i.CreateMessage1()
		check("CreateMessage1", err)
		_, err = i.ProcessMessage2([]byte{0x40})
		check("ProcessMessage2", err)
		check("ProcessMessage4", i.ProcessMessage4([]byte{0x40}))
		_, err = i.Export(0, nil, 16)
		check("Export", err)
		_, err = i.ExportOSCORE()
		check("ExportOSCORE", err)
		_, err = i.OSCORE(OSCOREParams{})
		check("OSCORE", err)
		_, err = i.PRKOut()
		check("PRKOut", err)
		check("KeyUpdate", i.KeyUpdate(nil))
		_ = i.ConnectionID()
		_ = i.PeerConnectionID()
		_ = i.PeerEAD()
		_ = i.PeerCredential()
		i.Close()
	}
	for _, r := range []*Responder{{}, nil} {
		_, err := r.ProcessMessage1([]byte{0x00})
		check("ProcessMessage1", err)
		check("ProcessMessage3", r.ProcessMessage3([]byte{0x40}))
		_, err = r.CreateMessage4()
		check("CreateMessage4", err)
		_, err = r.Export(0, nil, 16)
		check("Export", err)
		_, err = r.ExportOSCORE()
		check("ExportOSCORE", err)
		_, err = r.OSCORE(OSCOREParams{})
		check("OSCORE", err)
		_, err = r.PRKOut()
		check("PRKOut", err)
		check("KeyUpdate", r.KeyUpdate(nil))
		_ = r.ConnectionID()
		_ = r.PeerConnectionID()
		_ = r.PeerEAD()
		_ = r.PeerCredential()
		r.Close()
	}
}

// E7: an error message received in place of message_3 or message_4 is
// returned as the peer's *ErrorMessage, not a format error.
func TestE7_ErrorInPlaceOfMessage3And4(t *testing.T) {
	errBytes := []byte{0x01, 0x63, 'b', 'a', 'd'} // ERR_CODE 1, "bad"
	ini, res := pair(t, []byte{1}, []byte{2}, nil)
	m1, _ := ini.CreateMessage1()
	if _, err := res.ProcessMessage1(m1); err != nil {
		t.Fatal(err)
	}
	var em *ErrorMessage
	err := res.ProcessMessage3(errBytes)
	if !errors.As(err, &em) || !errors.Is(err, ErrPeerError) || em.Code != ErrCodeUnspecified || em.Info != "bad" {
		t.Errorf("error in place of message_3: %v, want the peer's *ErrorMessage", err)
	}

	ini, res = pair(t, []byte{1}, []byte{2}, nil)
	if err := handshake(t, ini, res); err != nil {
		t.Fatal(err)
	}
	err = ini.ProcessMessage4(errBytes)
	if !errors.As(err, &em) || em.Info != "bad" {
		t.Errorf("error in place of message_4: %v, want the peer's *ErrorMessage", err)
	}
}

// E11: received error messages follow RFC 9528 §6's field rules, and
// ERR_CODE 0 is never sent.
func TestE11_ErrorMessageFieldRules(t *testing.T) {
	for name, raw := range map[string][]byte{
		"ERR_CODE 0":             {0x00, 0xf5},
		"ERR_INFO missing":       {0x01},
		"ERR_CODE 1 not text":    {0x01, 0x05},
		"ERR_CODE 3 not true":    {0x03, 0xf4},
		"ERR_CODE 3 missing":     {0x03},
		"ERR_CODE 2 empty array": {0x02, 0x80},
	} {
		ini, _ := pair(t, []byte{1}, []byte{2}, nil)
		if _, err := ini.CreateMessage1(); err != nil {
			t.Fatal(err)
		}
		_, err := ini.ProcessMessage2(raw)
		var em *ErrorMessage
		if errors.As(err, &em) || !errors.Is(err, ErrMessageFormat) {
			t.Errorf("%s: %v, want ErrMessageFormat and no *ErrorMessage", name, err)
		}
	}
	for name, raw := range map[string][]byte{
		"ERR_CODE 1":        {0x01, 0x60},
		"ERR_CODE 3":        {0x03, 0xf5},
		"unregistered":      {0x18, 0x63, 0x01},
		"negative ERR_CODE": {0x20, 0x61, 'x'},
	} {
		ini, _ := pair(t, []byte{1}, []byte{2}, nil)
		if _, err := ini.CreateMessage1(); err != nil {
			t.Fatal(err)
		}
		var em *ErrorMessage
		if _, err := ini.ProcessMessage2(raw); !errors.As(err, &em) {
			t.Errorf("%s: %v, want *ErrorMessage", name, err)
		}
	}
	if _, err := (&ErrorMessage{Code: 0}).MarshalCBOR(); !errors.Is(err, ErrMessageFormat) {
		t.Errorf("MarshalCBOR(ERR_CODE 0): %v, want ErrMessageFormat", err)
	}
}

// E6: ErrorMessageFor turns any processing error into the error
// message to send, with fixed diagnostics that don't say which check
// failed.
func TestE6_ErrorMessageFor(t *testing.T) {
	if ErrorMessageFor(nil) != nil {
		t.Error("ErrorMessageFor(nil) != nil")
	}
	wire := func(err error) []byte {
		t.Helper()
		em := ErrorMessageFor(err)
		if em == nil {
			t.Fatalf("no error message for %v", err)
		}
		b, mErr := em.MarshalCBOR()
		if mErr != nil {
			t.Fatal(mErr)
		}
		return b
	}
	// Two different message_2 failures (parse and signature) produce the
	// same bytes.
	fail2 := func(flip func([]byte)) error {
		ini, res := pair(t, []byte{1}, []byte{2}, nil)
		m1, _ := ini.CreateMessage1()
		m2, err := res.ProcessMessage1(m1)
		if err != nil {
			t.Fatal(err)
		}
		flip(m2)
		_, err = ini.ProcessMessage2(m2)
		return err
	}
	sigErr := fail2(func(m []byte) { m[len(m)-1] ^= 1 })
	// m[34] is C_R, the first byte of PLAINTEXT_2 after the bstr head
	// and G_Y: 0x02 becomes 0xfd, a reserved head.
	fmtErr := fail2(func(m []byte) { m[34] ^= 0xff })
	if !errors.Is(sigErr, ErrAuthentication) || !errors.Is(fmtErr, ErrMessageFormat) {
		t.Fatalf("signature failure: %v; format failure: %v", sigErr, fmtErr)
	}
	a, b := wire(sigErr), wire(fmtErr)
	if !bytes.Equal(a, b) || !bytes.Equal(a, []byte{0x01, 0x70, 'm', 'e', 's', 's', 'a', 'g', 'e', ' ', 'r', 'e', 'j', 'e', 'c', 't', 'e', 'd'}) {
		t.Errorf("message_2 failures: %x and %x, want both (1, \"message rejected\")", a, b)
	}

	// A Responder's suite error is returned unchanged.
	ini, _ := pair(t, []byte{1}, []byte{2}, nil)
	m1, _ := ini.CreateMessage1()
	r2, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite2}, PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32)), PeerPublic: ed25519.PublicKey(make([]byte, 32)), ConnectionID: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r2.ProcessMessage1(m1)
	if em := ErrorMessageFor(err); em == nil || em.Code != ErrCodeWrongSelectedSuite {
		t.Errorf("suite error: %+v", em)
	}
	// The Initiator receiving it does not answer.
	raw, _ := ErrorMessageFor(err).MarshalCBOR()
	if _, err := ini.ProcessMessage2(raw); ErrorMessageFor(err) != nil {
		t.Errorf("answer to a received error message: %+v", ErrorMessageFor(err))
	}
	// Nor to a malformed one.
	ini, _ = pair(t, []byte{1}, []byte{2}, nil)
	_, _ = ini.CreateMessage1()
	if _, err := ini.ProcessMessage2([]byte{0x00, 0xf5}); ErrorMessageFor(err) != nil {
		t.Error("answer to ERR_CODE 0")
	}

	// An unknown kid is ERR_CODE 3.
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
		ic.Credential = &Credential{Raw: ccsWith(t, ic.PrivateKey.Public()), IDCred: IDCred{KID: []byte{0x2a}}}
	})
	err = handshake(t, ini, res)
	if !errors.Is(err, ErrUnknownCredential) || !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unknown kid: %v, want ErrUnknownCredential", err)
	}
	if got := wire(err); !bytes.Equal(got, []byte{0x03, 0xf5}) {
		t.Errorf("unknown kid: %x, want 03 f5", got)
	}
	// Using an endpoint out of order is "session aborted".
	if got := wire(errNoSession); !bytes.Contains(got, []byte("session aborted")) {
		t.Errorf("state violation: %x", got)
	}
}

// E8: an ID_CRED with several parameters, or ones this package does
// not interpret, reaches the resolver, and the received bytes (in any
// label order) enter the transcript.
func TestE8_IDCredOtherAndMultipleParams(t *testing.T) {
	for name, raw := range map[string][]byte{
		// {4: h'2a', 10: h'01'}: kid and kid context.
		"sorted": {0xa2, 0x04, 0x41, 0x2a, 0x0a, 0x41, 0x01},
		// The same, labels unsorted (RFC 9528 §3.5.3 allows it).
		"unsorted": {0xa2, 0x0a, 0x41, 0x01, 0x04, 0x41, 0x2a},
		// A text label.
		"text label": {0xa2, 0x04, 0x41, 0x2a, 0x61, 'p', 0xf5},
	} {
		var saw IDCred
		iPriv, iPub := edPair(t)
		ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
			ic.PrivateKey = iPriv
			v, err := corecbor.NewDecoder(seqDecOpts...).Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			id, err := parseIDCred(v, raw)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			ccs := ccsWith(t, iPub)
			ic.Credential = &Credential{Raw: ccs, IDCred: id}
			rc.Peers = resolverFunc(func(_ context.Context, id IDCred) (*Credential, error) {
				saw = id
				return &Credential{Raw: ccs, IDCred: id, PublicKey: iPub}, nil
			})
		})
		if err := handshake(t, ini, res); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(saw.KID, []byte{0x2a}) || len(saw.Other) != 1 || !bytes.Equal(saw.Raw, raw) {
			t.Errorf("%s: resolver saw %+v", name, saw)
		}
	}
}

// cwtFor signs a CWT whose cnf holds subject, after mut adjusts the
// claims.
func cwtFor(t *testing.T, issuer ed25519.PrivateKey, subject ed25519.PublicKey, mut func(*cwt.ClaimsSet)) []byte {
	t.Helper()
	k, err := cose.NewKeyFromPublic(subject)
	if err != nil {
		t.Fatal(err)
	}
	claims := &cwt.ClaimsSet{Subject: "edhoc-peer", Confirmation: &cwt.Confirmation{Key: k}}
	if mut != nil {
		mut(claims)
	}
	signer, err := cose.NewSigner(issuer)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cwt.Sign(claims, signer)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cwtPair runs a handshake where the Initiator sends a CWT by value
// (kcwt) that the Responder verifies with CWTIssuerKey.
func cwtPair(t *testing.T, mut func(*cwt.ClaimsSet), rmut func(*ResponderConfig)) error {
	t.Helper()
	iPriv, iPub := edPair(t)
	rPriv, rPub := edPair(t)
	caPriv, caPub := edPair(t)
	tok := cwtFor(t, caPriv, iPub, mut)
	ic := InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: []byte{1},
		Credential: &Credential{Type: CredentialCWT, CWTBytes: tok}}
	rc := ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, CWTIssuerKey: caPub, ConnectionID: []byte{2}}
	if rmut != nil {
		rmut(&rc)
	}
	ini, err := NewInitiator(ic)
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(rc)
	if err != nil {
		t.Fatal(err)
	}
	return handshake(t, ini, res)
}

// E1: a CWT sent by value is validated, not just signature-checked.
func TestE1_CWTClaimsValidated(t *testing.T) {
	now := time.Now()
	if err := cwtPair(t, func(c *cwt.ClaimsSet) { c.Expiration = now.Add(-time.Hour) }, nil); !errors.Is(err, cwt.ErrTokenExpired) || !errors.Is(err, ErrAuthentication) {
		t.Errorf("expired CWT: err = %v, want cwt.ErrTokenExpired and ErrAuthentication", err)
	}
	if err := cwtPair(t, func(c *cwt.ClaimsSet) { c.Expiration = now.Add(time.Hour); c.NotBefore = now.Add(time.Hour) }, nil); !errors.Is(err, cwt.ErrTokenNotYetValid) {
		t.Errorf("not-yet-valid CWT: err = %v, want cwt.ErrTokenNotYetValid", err)
	}
	// cwt.NewValidator requires exp.
	if err := cwtPair(t, nil, nil); !errors.Is(err, cwt.ErrMissingExpiration) {
		t.Errorf("CWT without exp: err = %v, want cwt.ErrMissingExpiration", err)
	}
	if err := cwtPair(t, func(c *cwt.ClaimsSet) { c.Expiration = now.Add(time.Hour) }, nil); err != nil {
		t.Errorf("valid CWT: %v", err)
	}
	// A caller-supplied validator: audience and clock.
	withAud := func(rc *ResponderConfig) {
		v := cwt.NewValidator()
		v.Audience = "coap://rs.example"
		rc.CWTValidator = v
	}
	if err := cwtPair(t, func(c *cwt.ClaimsSet) { c.Expiration = now.Add(time.Hour) }, withAud); !errors.Is(err, cwt.ErrAudienceMismatch) {
		t.Errorf("wrong audience: err = %v, want cwt.ErrAudienceMismatch", err)
	}
	past := func(rc *ResponderConfig) {
		v := cwt.NewValidator()
		v.Now = func() time.Time { return now.Add(-2 * time.Hour) }
		rc.CWTValidator = v
	}
	if err := cwtPair(t, func(c *cwt.ClaimsSet) { c.Expiration = now.Add(-time.Hour) }, past); err != nil {
		t.Errorf("custom clock: %v", err)
	}
}

// ccsWith returns a CCS {extra..., 8: {1: COSE_Key(pub)}}.
func ccsWith(t *testing.T, pub crypto.PublicKey, extra ...cbor.MapEntry) []byte {
	t.Helper()
	k, err := coseKeyOf(pub)
	if err != nil {
		t.Fatal(err)
	}
	cnf := cbor.MakeMap(cbor.MapEntry{Key: cbor.Uint(cnfCOSEKey), Value: k})
	return item(cbor.MakeMap(append(extra, cbor.MapEntry{Key: cbor.Uint(ccsClaimCnf), Value: cnf})...))
}

// E1: a CCS sent by value has no issuer signature, but its exp and nbf
// claims, when present, are checked with the same validator's clock.
func TestE1_CCSTimeClaimsChecked(t *testing.T) {
	run := func(extra ...cbor.MapEntry) error {
		iPriv, iPub := edPair(t)
		ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
			ic.PrivateKey = iPriv
			ic.Credential = &Credential{Raw: ccsWith(t, iPub, extra...)}
			rc.PeerPublic = iPub
		})
		return handshake(t, ini, res)
	}
	now := time.Now().Unix()
	if err := run(cbor.MapEntry{Key: cbor.Uint(4), Value: cbor.Uint(uint64(now - 3600))}); !errors.Is(err, cwt.ErrTokenExpired) {
		t.Errorf("expired CCS: err = %v, want cwt.ErrTokenExpired", err)
	}
	if err := run(cbor.MapEntry{Key: cbor.Uint(5), Value: cbor.Uint(uint64(now + 3600))}); !errors.Is(err, cwt.ErrTokenNotYetValid) {
		t.Errorf("not-yet-valid CCS: err = %v, want cwt.ErrTokenNotYetValid", err)
	}
	if err := run(cbor.MapEntry{Key: cbor.Uint(4), Value: cbor.Text("soon")}); !errors.Is(err, ErrAuthentication) {
		t.Errorf("malformed exp: err = %v, want ErrAuthentication", err)
	}
	// No exp is fine for a CCS (RFC 9529's have none).
	if err := run(cbor.MapEntry{Key: cbor.Uint(4), Value: cbor.Uint(uint64(now + 3600))}); err != nil {
		t.Errorf("valid CCS: %v", err)
	}
	if err := run(); err != nil {
		t.Errorf("CCS without time claims: %v", err)
	}
}
