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
	"go/ast"
	"go/parser"
	"go/token"
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
		res, err := NewResponder(ResponderConfig{
			Suites: []CipherSuite{Suite2}, Method: method, PrivateKey: rSig, ConnectionID: []byte{2},
			Peers: resolverFunc(func(context.Context, IDCred) (*Credential, error) {
				return &Credential{Raw: ccs, PublicKey: iPub}, nil
			}),
		})
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
		{"ESP256 key for static DH", MethodStatSig, cose.AlgESP256, nil},
		{"ES256 key for static DH", MethodStatSig, cose.Algorithm(-7), nil},
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
	if err := run(MethodSigSig, true, cose.Algorithm(-7), cose.KeyOpVerify); err != nil { // ES256
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

// E14: a one-certificate x5chain must be a byte string (RFC 9360 §2);
// the array form would be re-encoded differently.
func TestE14_OneElementX5ChainArray(t *testing.T) {
	cert := []byte{0x30, 0x00}
	arr := []byte{0xa1, 0x18, 0x21, 0x81, 0x42, 0x30, 0x00} // {33: [h'3000']}
	v, err := corecbor.NewDecoder(seqDecOpts...).Decode(arr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseIDCred(v, arr); !errors.Is(err, ErrMessageFormat) {
		t.Errorf("one-element x5chain array: %v, want ErrMessageFormat", err)
	}
	bs := []byte{0xa1, 0x18, 0x21, 0x42, 0x30, 0x00} // {33: h'3000'}
	v, _ = corecbor.NewDecoder(seqDecOpts...).Decode(bs)
	if id, err := parseIDCred(v, bs); err != nil || len(id.X5Chain) != 1 || !bytes.Equal(id.X5Chain[0], cert) {
		t.Errorf("byte-string x5chain: %+v, %v", id, err)
	}
}

// E15: CRED_x for a CWT is the untagged CWT, even when kcwt carries it
// with the CWT tag (RFC 9528 §3.5.2).
func TestE15_TaggedKCWTIsUntaggedCRED(t *testing.T) {
	iPriv, iPub := edPair(t)
	rPriv, rPub := edPair(t)
	caPriv, caPub := edPair(t)
	tok := cwtFor(t, caPriv, iPub, func(c *cwt.ClaimsSet) { c.Expiration = time.Now().Add(time.Hour) })
	tagged := append([]byte{0xd8, 0x3d}, tok...) // 61(CWT)
	ini, err := NewInitiator(InitiatorConfig{
		Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: []byte{1},
		Credential: &Credential{Type: CredentialCWT, CWTBytes: tagged},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, CWTIssuerKey: caPub, ConnectionID: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, ini, res); err != nil {
		t.Fatal(err)
	}
	if got := ini.s.ownCred.Raw; !bytes.Equal(got, tok) {
		t.Errorf("own CRED_I starts %x, want the untagged CWT", got[:4])
	}
	pc := res.PeerCredential()
	if !bytes.Equal(pc.Raw, tok) || !bytes.Equal(pc.IDCred.KCWT, tagged) {
		t.Errorf("peer CRED_I starts %x (kcwt %x), want the untagged CWT and kcwt as sent", pc.Raw[:4], pc.IDCred.KCWT[:4])
	}
}

// E9, E10: received messages must be deterministically encoded, and a
// connection identifier that is a one-byte integer must be sent as one;
// AcceptNonDeterministicEncoding opts out.
func TestE9_E10_DeterministicInput(t *testing.T) {
	ini, _ := pair(t, []byte{1}, []byte{2}, nil)
	m1, err := ini.CreateMessage1()
	if err != nil {
		t.Fatal(err)
	}
	// message_1 = METHOD 00, SUITES_I 00, G_X 5820..., C_I 01.
	nonShortest := append([]byte{0x18, 0x00}, m1[1:]...) // METHOD as 0x1800
	bstrCI := append(bytes.Clone(m1[:len(m1)-1]), 0x41, 0x01)
	for name, msg := range map[string][]byte{"non-shortest METHOD": nonShortest, "C_I as h'01'": bstrCI} {
		for _, lenient := range []bool{false, true} {
			_, res := pair(t, nil, []byte{2}, func(_ *InitiatorConfig, rc *ResponderConfig) {
				rc.AcceptNonDeterministicEncoding = lenient
			})
			_, err := res.ProcessMessage1(msg)
			switch {
			case !lenient && !errors.Is(err, ErrMessageFormat):
				t.Errorf("%s: %v, want ErrMessageFormat", name, err)
			case lenient && err != nil:
				t.Errorf("%s with AcceptNonDeterministicEncoding: %v", name, err)
			}
		}
	}
	// Error messages too: ERR_CODE 1 encoded as 0x1801.
	ini, _ = pair(t, []byte{1}, []byte{2}, nil)
	_, _ = ini.CreateMessage1()
	_, err = ini.ProcessMessage2([]byte{0x18, 0x01, 0x61, 'x'})
	var em *ErrorMessage
	if errors.As(err, &em) || !errors.Is(err, ErrMessageFormat) {
		t.Errorf("non-shortest ERR_CODE: %v, want ErrMessageFormat", err)
	}
}

// E12: an OSCORE context is not exported with a Sender or Recipient ID
// longer than the AEAD nonce allows (RFC 8613 §3.3).
func TestE12_OSCOREIDLength(t *testing.T) {
	for _, c := range []struct {
		ci, cr []byte
		ok     bool
	}{
		{bytes.Repeat([]byte{0xaa}, 7), []byte{2}, true}, // suite 0: AES-CCM, 13-byte nonce: 7
		{bytes.Repeat([]byte{0xaa}, 8), []byte{2}, false},
		{[]byte{1}, bytes.Repeat([]byte{0xbb}, 8), false},
	} {
		ini, res := pair(t, c.ci, c.cr, nil)
		if err := handshake(t, ini, res); err != nil {
			t.Fatal(err)
		}
		for name, f := range map[string]func() (*OSCOREContext, error){
			"initiator": ini.ExportOSCORE, "responder": res.ExportOSCORE,
			"initiator OSCORE": func() (*OSCOREContext, error) { return ini.OSCORE(OSCOREParams{}) },
		} {
			_, err := f()
			if c.ok != (err == nil) || (!c.ok && !errors.Is(err, ErrStateViolation)) {
				t.Errorf("%s with C_I %d bytes, C_R %d bytes: %v", name, len(c.ci), len(c.cr), err)
			}
		}
	}
}

// E13: PLAINTEXT_2 longer than KEYSTREAM_2 can cover (255 hash
// lengths) is refused with an error that says so, on both sides.
func TestE13_Plaintext2Size(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, func(_ *InitiatorConfig, rc *ResponderConfig) {
		rc.EAD2 = []EADItem{{Label: 5, Value: make([]byte, 255*32)}}
	})
	m1, _ := ini.CreateMessage1()
	if _, err := res.ProcessMessage1(m1); !errors.Is(err, ErrStateViolation) || !strings.Contains(err.Error(), "PLAINTEXT_2") {
		t.Errorf("oversized EAD_2: %v, want ErrStateViolation naming PLAINTEXT_2", err)
	}
	ini, _ = pair(t, []byte{1}, []byte{2}, nil)
	_, _ = ini.CreateMessage1()
	body := make([]byte, 32+255*32+1)
	body[0] = 9 // a valid X25519 u-coordinate
	if _, err := ini.ProcessMessage2(bstrItem(body)); !errors.Is(err, ErrMessageFormat) || !strings.Contains(err.Error(), "PLAINTEXT_2") {
		t.Errorf("oversized message_2: %v, want ErrMessageFormat naming PLAINTEXT_2", err)
	}
}

// E16: intermediate keys are deleted once derived from (RFC 9528 §9),
// not kept until Close.
func TestE16_IntermediateValuesDeleted(t *testing.T) {
	for _, m := range []Method{MethodSigSig, MethodStatStat} {
		ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
			if m == MethodStatStat {
				iDH, _ := ecdh.X25519().GenerateKey(rand.Reader)
				rDH, _ := ecdh.X25519().GenerateKey(rand.Reader)
				ic.Method, ic.DHKey, ic.PeerPublic = m, iDH, rDH.PublicKey()
				rc.Method, rc.DHKey, rc.PeerPublic = m, rDH, iDH.PublicKey()
			}
		})
		m1, _ := ini.CreateMessage1()
		m2, err := res.ProcessMessage1(m1)
		if err != nil {
			t.Fatal(err)
		}
		if s := res.s; s.prk2e != nil || s.th2 != nil || s.hMsg1 != nil {
			t.Errorf("method %d: Responder keeps PRK_2e/TH_2/H(message_1) after message_2", m)
		}
		m3, err := ini.ProcessMessage2(m2)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.ProcessMessage3(m3); err != nil {
			t.Fatal(err)
		}
		for name, s := range map[string]*session{"Initiator": ini.s, "Responder": res.s} {
			if s.eph != nil || s.prk2e != nil || s.prk3e2m != nil || s.prk4e3m != nil || s.th2 != nil || s.th3 != nil || s.th4 != nil || s.hMsg1 != nil {
				t.Errorf("method %d: %s keeps intermediate values after completion", m, name)
			}
			if s.prkOut == nil || s.prkExporter == nil {
				t.Errorf("method %d: %s lost PRK_out/PRK_exporter", m, name)
			}
		}
		m4, err := res.CreateMessage4()
		if err != nil {
			t.Fatal(err)
		}
		if err := ini.ProcessMessage4(m4); err != nil {
			t.Fatal(err)
		}
		if ini.s.k4 != nil || res.s.k4 != nil {
			t.Errorf("method %d: K_4 kept after message_4", m)
		}
	}
}

// E17: Rand is documented as insecure and for tests only, on both
// configs.
func TestE17_RandFlaggedTestOnly(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "config.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || (ts.Name.Name != "InitiatorConfig" && ts.Name.Name != "ResponderConfig") {
			return true
		}
		for _, fld := range ts.Type.(*ast.StructType).Fields.List {
			if len(fld.Names) == 0 || fld.Names[0].Name != "Rand" {
				continue
			}
			found++
			doc := fld.Doc.Text()
			if !strings.Contains(doc, "INSECURE") || !strings.Contains(doc, "tests only") {
				t.Errorf("%s.Rand doc does not flag it as insecure and for tests only:\n%s", ts.Name.Name, doc)
			}
		}
		return false
	})
	if found != 2 {
		t.Fatalf("found %d Rand fields, want 2", found)
	}
}

// E18: the critical-EAD callback can tell which message an item came in.
func TestE18_CriticalEADMessageNumber(t *testing.T) {
	run := func(ead1, ead3 []EADItem) ([]int, error) {
		var seen []int
		ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
			ic.EAD1, ic.EAD3 = ead1, ead3
			rc.AcceptCriticalEAD = func(EADItem) bool { return true } // overridden
			rc.AcceptCriticalEADInMessage = func(msg int, e EADItem) bool {
				seen = append(seen, msg)
				return msg == 3 && e.Label == 9
			}
		})
		err := handshake(t, ini, res)
		return seen, err
	}
	crit := []EADItem{{Label: 9, Critical: true}}
	if seen, err := run(nil, crit); err != nil || len(seen) != 1 || seen[0] != 3 {
		t.Errorf("critical item in EAD_3: %v (messages %v)", err, seen)
	}
	if seen, err := run(crit, nil); !errors.Is(err, ErrCriticalEAD) || len(seen) != 1 || seen[0] != 1 {
		t.Errorf("critical item in EAD_1: %v (messages %v), want ErrCriticalEAD", err, seen)
	}
}

// E20: message size, EAD item count and certificate count are bounded,
// by default and as configured.
func TestE20_Limits(t *testing.T) {
	// Message size: a message_1 over the default is refused unread.
	_, res := pair(t, nil, []byte{2}, nil)
	if _, err := res.ProcessMessage1(make([]byte, DefaultMaxMessageSize+1)); !errors.Is(err, ErrMessageFormat) || !strings.Contains(err.Error(), "MaxMessageSize") {
		t.Errorf("oversized message_1: %v", err)
	}
	// EAD items: the default allows DefaultMaxEADItems.
	many := func(n int) []EADItem {
		items := make([]EADItem, n)
		for i := range items {
			items[i] = EADItem{Label: uint64(100 + i)}
		}
		return items
	}
	for _, c := range []struct {
		n, limit int
		ok       bool
	}{{DefaultMaxEADItems, 0, true}, {DefaultMaxEADItems + 1, 0, false}, {3, 2, false}, {2, 2, true}} {
		ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, rc *ResponderConfig) {
			ic.EAD1 = many(c.n)
			rc.Limits.MaxEADItems = c.limit
		})
		m1, _ := ini.CreateMessage1()
		_, err := res.ProcessMessage1(m1)
		if c.ok != (err == nil) || (!c.ok && !strings.Contains(err.Error(), "MaxEADItems")) {
			t.Errorf("%d EAD items, limit %d: %v", c.n, c.limit, err)
		}
	}
	// Certificates in x5chain.
	pki := newTestPKI(t)
	iKey, chain := pki.leaf(t, "initiator")
	long := append(chain, chain[1], chain[1]) // leaf + 3 intermediates
	iCred, _ := X509Credential(long, false)
	rKey, rChain := pki.leaf(t, "responder")
	rCred, _ := X509Credential(rChain, false)
	for _, c := range []struct {
		limit int
		ok    bool
	}{{0, true}, {3, false}, {4, true}} {
		ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iKey, ConnectionID: []byte{1}, Credential: iCred, Peers: X509Resolver(pki.policy())})
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(ResponderConfig{
			Suites: []CipherSuite{Suite0}, PrivateKey: rKey, ConnectionID: []byte{2}, Credential: rCred, Peers: X509Resolver(pki.policy()),
			Limits: Limits{MaxCertificates: c.limit},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = handshake(t, ini, res)
		if c.ok != (err == nil) || (!c.ok && !strings.Contains(err.Error(), "MaxCertificates")) {
			t.Errorf("4 certificates, limit %d: %v", c.limit, err)
		}
	}
	if _, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iKey, PeerPublic: iKey.Public(), Limits: Limits{MaxMessageSize: -1}}); !errors.Is(err, ErrStateViolation) {
		t.Errorf("negative limit: %v", err)
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
	ic := InitiatorConfig{
		Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: []byte{1},
		Credential: &Credential{Type: CredentialCWT, CWTBytes: tok},
	}
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

// E14: AllowSingleCertX5ChainArray accepts the one-certificate array
// form, with the received bytes in the transcript.
func TestE14_AllowSingleCertX5ChainArray(t *testing.T) {
	for _, allow := range []bool{false, true} {
		pki := newTestPKI(t)
		iKey, chain := pki.leaf(t, "initiator")
		rKey, rChain := pki.leaf(t, "responder")
		rCred, _ := X509Credential(rChain, false)
		// {33: [leaf]}
		raw := append([]byte{0xa1, 0x18, 0x21, 0x81}, bstrItem(chain[0])...)
		iCred := &Credential{Raw: bstrItem(chain[0]), IDCred: IDCred{X5Chain: chain[:1], Raw: raw}}
		ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iKey, ConnectionID: []byte{1}, Credential: iCred, Peers: X509Resolver(pki.policy())})
		if err != nil {
			t.Fatal(err)
		}
		// The intermediate comes from the policy, as the peer sent only
		// the leaf.
		p := pki.policy()
		p.Intermediates = x509.NewCertPool()
		p.Intermediates.AddCert(pki.inter)
		res, err := NewResponder(ResponderConfig{
			Suites: []CipherSuite{Suite0}, PrivateKey: rKey, ConnectionID: []byte{2}, Credential: rCred, Peers: X509Resolver(p),
			AllowSingleCertX5ChainArray: allow,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = handshake(t, ini, res)
		switch {
		case !allow && !errors.Is(err, ErrMessageFormat):
			t.Errorf("default: %v, want ErrMessageFormat", err)
		case allow && err != nil:
			t.Errorf("AllowSingleCertX5ChainArray: %v", err)
		case allow && !bytes.Equal(res.PeerCredential().IDCred.Raw, raw):
			t.Error("received ID_CRED bytes not kept")
		}
	}
}

// E1 in the legacy pre-RFC protocol: a CWT credential's claims are
// validated there too.
func TestE1_LegacyCWTClaimsValidated(t *testing.T) {
	run := func(exp time.Time, v *cwt.Validator) error {
		iPriv, iPub := edPair(t)
		rPriv, rPub := edPair(t)
		set := func(c *cwt.ClaimsSet) { c.Expiration = exp }
		iCWT, rCWT := cwtFor(t, iPriv, iPub, set), cwtFor(t, rPriv, rPub, set)
		ini, err := NewInitiator(InitiatorConfig{
			Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: []byte{0x50},
			Credential:     &Credential{Type: CredentialCWT, CWTBytes: iCWT},
			PeerCredential: &Credential{Type: CredentialCWT, CWTBytes: rCWT},
			CWTIssuerKey:   rPub, CWTValidator: v,
		}, WithLegacyPreRFCProtocol())
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(ResponderConfig{
			Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, PeerPublic: iPub, ConnectionID: []byte{0x51},
			Credential:     &Credential{Type: CredentialCWT, CWTBytes: rCWT},
			PeerCredential: &Credential{Type: CredentialCWT, CWTBytes: iCWT},
			CWTIssuerKey:   iPub, CWTValidator: v,
		}, WithLegacyPreRFCProtocol())
		if err != nil {
			t.Fatal(err)
		}
		return handshake(t, ini, res)
	}
	now := time.Now()
	if err := run(now.Add(time.Hour), nil); err != nil {
		t.Errorf("valid CWT: %v", err)
	}
	if err := run(now.Add(-time.Hour), nil); !errors.Is(err, cwt.ErrTokenExpired) || !errors.Is(err, ErrAuthentication) {
		t.Errorf("expired CWT: %v, want cwt.ErrTokenExpired", err)
	}
	past := cwt.NewValidator()
	past.Now = func() time.Time { return now.Add(-2 * time.Hour) }
	if err := run(now.Add(-time.Hour), past); err != nil {
		t.Errorf("custom clock: %v", err)
	}
}
