// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

type testPKI struct {
	roots *x509.CertPool
	caKey *ecdsa.PrivateKey
	ca    *x509.Certificate
	inKey *ecdsa.PrivateKey
	inter *x509.Certificate
	now   time.Time
	// leafUsage, when set, replaces the end-entity keyUsage.
	leafUsage x509.KeyUsage
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	var err error
	p.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.ca = p.cert(t, "root", p.caKey.Public(), nil, nil, true, p.now.Add(-time.Hour), p.now.Add(time.Hour))
	p.inKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.inter = p.cert(t, "intermediate", p.inKey.Public(), p.ca, p.caKey, true, p.now.Add(-time.Hour), p.now.Add(time.Hour))
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.ca)
	return p
}

var serial int64

func (p *testPKI) cert(t *testing.T, cn string, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer, isCA bool, from, to time.Time) *x509.Certificate {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             from,
		NotAfter:              to,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if !isCA && p.leafUsage != 0 {
		tmpl.KeyUsage = p.leafUsage
	}
	if parent == nil {
		parent = tmpl
		signer = p.caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// leaf issues an Ed25519 end-entity certificate under the intermediate
// and returns its key and chain (leaf, intermediate).
func (p *testPKI) leaf(t *testing.T, cn string) (ed25519.PrivateKey, [][]byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := p.cert(t, cn, pub, p.inter, p.inKey, false, p.now.Add(-time.Minute), p.now.Add(time.Minute))
	return priv, [][]byte{c.Raw, p.inter.Raw}
}

// policy accepts any peer under the test roots; tests of the identity
// check set VerifyPeer.
func (p *testPKI) policy() X509Policy {
	return X509Policy{Roots: p.roots, CurrentTime: p.now, AllowAnyPeerUnderRoots: true}
}

// The Initiator sends its chain by value (x5chain); the Responder sends
// an x5t reference that the Initiator resolves through Certificates.
func TestX509_Handshake(t *testing.T) {
	pki := newTestPKI(t)
	iKey, iChain := pki.leaf(t, "initiator")
	rKey, rChain := pki.leaf(t, "responder")

	iCred, err := X509Credential(iChain, false)
	if err != nil {
		t.Fatal(err)
	}
	rCred, err := X509Credential(rChain, true)
	if err != nil {
		t.Fatal(err)
	}
	if rCred.IDCred.X5T == nil || !rCred.IDCred.X5T.Matches(rChain[0]) {
		t.Fatal("by-reference credential has no matching x5t")
	}
	if !bytes.Equal(iCred.Raw, bstrItem(iChain[0])) {
		t.Fatal("CRED_x is not the DER leaf as a byte string")
	}

	var looked int
	iPolicy := pki.policy()
	iPolicy.Certificates = func(_ context.Context, x X5T) ([][]byte, error) {
		looked++
		if x.Matches(rChain[0]) {
			return rChain, nil
		}
		return nil, errors.New("unknown certificate")
	}
	var sawCN string
	rPolicy := pki.policy()
	rPolicy.VerifyPeer = func(leaf *x509.Certificate) error {
		sawCN = leaf.Subject.CommonName
		return nil
	}

	ini, err := NewInitiator(InitiatorConfig{
		Suites: []CipherSuite{Suite0}, PrivateKey: iKey, ConnectionID: []byte{1},
		Credential: iCred, Peers: X509Resolver(iPolicy),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(ResponderConfig{
		Suites: []CipherSuite{Suite0}, PrivateKey: rKey, ConnectionID: []byte{2},
		Credential: rCred, Peers: X509Resolver(rPolicy),
	})
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := ini.CreateMessage1()
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := res.ProcessMessage1(msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg3, err := ini.ProcessMessage2(msg2)
	if err != nil {
		t.Fatalf("ProcessMessage2: %v", err)
	}
	if err := res.ProcessMessage3(msg3); err != nil {
		t.Fatalf("ProcessMessage3: %v", err)
	}
	if looked != 1 {
		t.Fatalf("x5t lookups = %d, want 1", looked)
	}
	if sawCN != "initiator" {
		t.Fatalf("VerifyPeer saw %q", sawCN)
	}
	if pc := ini.PeerCredential(); pc == nil || !bytes.Equal(pc.Raw, bstrItem(rChain[0])) {
		t.Fatal("Initiator.PeerCredential is not the responder's leaf")
	}
}

func TestX509_Rejections(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t)
	_, chain := pki.leaf(t, "peer")
	_, foreign := other.leaf(t, "stranger")

	expired := pki.policy()
	expired.CurrentTime = pki.now.Add(2 * time.Hour)
	veto := pki.policy()
	veto.VerifyPeer = func(*x509.Certificate) error { return errors.New("not allowed") }
	wrongLookup := pki.policy()
	wrongLookup.Certificates = func(context.Context, X5T) ([][]byte, error) { return foreign, nil }

	ref, err := X509Credential(chain, true)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		p  X509Policy
		id IDCred
	}{
		"untrusted chain":       {pki.policy(), IDCred{X5Chain: foreign}},
		"expired":               {expired, IDCred{X5Chain: chain}},
		"VerifyPeer veto":       {veto, IDCred{X5Chain: chain}},
		"no Roots":              {X509Policy{CurrentTime: pki.now}, IDCred{X5Chain: chain}},
		"x5t without lookup":    {pki.policy(), ref.IDCred},
		"x5t lookup mismatched": {wrongLookup, ref.IDCred},
		"not X.509":             {pki.policy(), IDCred{KID: []byte{1}}},
		"garbage certificate":   {pki.policy(), IDCred{X5Chain: [][]byte{{0x30, 0x00}}}},
	} {
		if _, err := X509Resolver(tc.p).ResolveCredential(context.Background(), tc.id); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s: err = %v, want ErrAuthentication", name, err)
		}
	}
	// The happy path for the same inputs.
	if _, err := X509Resolver(pki.policy()).ResolveCredential(context.Background(), IDCred{X5Chain: chain}); err != nil {
		t.Fatalf("valid chain: %v", err)
	}
}

// A handshake against an untrusted certificate fails at the Initiator,
// which then refuses further use.
func TestX509_UntrustedPeerFailsHandshake(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t)
	iKey, iChain := pki.leaf(t, "initiator")
	rKey, rChain := other.leaf(t, "responder")
	iCred, _ := X509Credential(iChain, false)
	rCred, _ := X509Credential(rChain, false)
	ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iKey, ConnectionID: []byte{1}, Credential: iCred, Peers: X509Resolver(pki.policy())})
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rKey, ConnectionID: []byte{2}, Credential: rCred, Peers: X509Resolver(other.policy())})
	if err != nil {
		t.Fatal(err)
	}
	msg1, _ := ini.CreateMessage1()
	msg2, err := res.ProcessMessage1(msg1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ini.ProcessMessage2(msg2); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ProcessMessage2 err = %v, want ErrAuthentication", err)
	}
	if _, err := ini.ExportOSCORE(); err == nil {
		t.Fatal("ExportOSCORE after a failed handshake must fail")
	}
}

// FuzzX509ResolverNeverPanics: arbitrary certificate bytes from a peer
// are rejected with ErrAuthentication or accepted; never a panic.
func FuzzX509ResolverNeverPanics(f *testing.F) {
	f.Add([]byte{0x30, 0x00}, []byte{})
	f.Add([]byte{}, []byte{0x30, 0x03, 0x02, 0x01, 0x00})
	r := X509Resolver(X509Policy{Roots: x509.NewCertPool(), AllowAnyPeerUnderRoots: true})
	f.Fuzz(func(t *testing.T, leaf, inter []byte) {
		_, err := r.ResolveCredential(context.Background(), IDCred{X5Chain: [][]byte{leaf, inter}})
		if err != nil && !errors.Is(err, ErrAuthentication) {
			t.Fatalf("err = %v, want ErrAuthentication", err)
		}
		_, err = X509Credential([][]byte{leaf}, true)
		if err != nil && !errors.Is(err, ErrMessageFormat) && !errors.Is(err, ErrAuthentication) {
			t.Fatalf("X509Credential err = %v", err)
		}
	})
}
