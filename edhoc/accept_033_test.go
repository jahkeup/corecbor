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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"strings"
	"testing"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
)

// Acceptance tests named by proposal 033's criteria.

func handshake(t *testing.T, ini *Initiator, res *Responder) error {
	t.Helper()
	m1, err := ini.CreateMessage1()
	if err != nil {
		return err
	}
	m2, err := res.ProcessMessage1(m1)
	if err != nil {
		return err
	}
	m3, err := ini.ProcessMessage2(m2)
	if err != nil {
		return err
	}
	return res.ProcessMessage3(m3)
}

func TestIDCred_Parse(t *testing.T) {
	dec := corecbor.NewDecoder()
	for name, tc := range map[string]struct {
		hex  string
		want func(IDCred) bool
	}{
		"compact kid int":  {"05", func(id IDCred) bool { return bytes.Equal(id.KID, []byte{5}) }},
		"compact kid -1":   {"20", func(id IDCred) bool { return bytes.Equal(id.KID, []byte{0x20}) }},
		"compact kid bstr": {"4118", func(id IDCred) bool { return bytes.Equal(id.KID, []byte{0x18}) }},
		"kid map":          {"a1044105", func(id IDCred) bool { return bytes.Equal(id.KID, []byte{5}) }},
		"x5t": {"a1182282" + "2e" + "48" + "0102030405060708", func(id IDCred) bool {
			return id.X5T != nil && id.X5T.Alg == -15 && bytes.Equal(id.X5T.Hash, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		}},
		"kccs": {"a10ea1" + "0801", func(id IDCred) bool { return bytes.Equal(id.KCCS, []byte{0xa1, 0x08, 0x01}) }},
	} {
		v, err := dec.Decode(unhex(t, tc.hex))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		id, err := ParseIDCred(v)
		if err != nil || !tc.want(id) {
			t.Errorf("%s: ParseIDCred = %+v, %v", name, id, err)
		}
	}
}

// The resolver receives the parsed ID_CRED, and its error is wrapped
// by ErrCredentialRejected (and ErrAuthentication).
func TestIDCred_ResolverErrorWrapped(t *testing.T) {
	sentinel := errors.New("not in directory")
	var got IDCred
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, _ *ResponderConfig) {
		ic.PeerPublic = nil
		ic.Peers = resolverFunc(func(_ context.Context, id IDCred) (*Credential, error) {
			got = id
			return nil, sentinel
		})
	})
	err := handshake(t, ini, res)
	if !errors.Is(err, ErrCredentialRejected) || !errors.Is(err, ErrAuthentication) || !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want ErrCredentialRejected + ErrAuthentication + cause", err)
	}
	if got.KCCS == nil {
		t.Fatalf("resolver received %+v, want the responder's kccs", got)
	}
}

type resolverFunc func(context.Context, IDCred) (*Credential, error)

func (f resolverFunc) ResolveCredential(ctx context.Context, id IDCred) (*Credential, error) {
	return f(ctx, id)
}

// A CWT credential is never verified with PeerPublic as the issuer key:
// without CWTIssuerKey it is rejected.
func TestCredential_NoIssuerFallback(t *testing.T) {
	iPriv, iPub := edPair(t)
	rPriv, rPub := edPair(t)
	rCWT := createTestCWT(t, rPriv, rPub) // self-issued: PeerPublic would verify it
	ic := InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: []byte{1}}
	ini, err := NewInitiator(ic)
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(ResponderConfig{
		Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, PeerPublic: iPub, ConnectionID: []byte{2},
		Credential: &Credential{Type: CredentialCWT, CWTBytes: rCWT},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, ini, res); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v, want ErrAuthentication", err)
	}
	if ic.CWTIssuerKey != nil {
		t.Fatal("config was modified")
	}
}

// An EC2 credential key whose point is not on the curve is rejected.
func TestCredential_OffCurve(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x, y := raw[1:33], append([]byte{}, raw[33:]...)
	y[31] ^= 1 // move the point off the curve
	key := cbor.MakeMap(
		cbor.MapEntry{Key: intVal(coseKeyKty), Value: intVal(ktyEC2)},
		cbor.MapEntry{Key: intVal(coseKeyCrv), Value: intVal(crvP256)},
		cbor.MapEntry{Key: intVal(coseKeyX), Value: cbor.Bytes(x)},
		cbor.MapEntry{Key: intVal(coseKeyY), Value: cbor.Bytes(y)},
	)
	if _, err := publicFromCOSEKey(key); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("off-curve key: err = %v, want ErrAuthentication", err)
	}
}

// opaqueSigner hides the concrete key type, like a KMS-backed signer.
type opaqueSigner struct{ s crypto.Signer }

func (o opaqueSigner) Public() crypto.PublicKey { return o.s.Public() }
func (o opaqueSigner) Sign(r io.Reader, d []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.s.Sign(r, d, opts)
}

func TestPrivateKey_GenericSigner(t *testing.T) {
	newP256 := func() crypto.Signer {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	newEd := func() crypto.Signer {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	for _, tc := range []struct {
		suite CipherSuite
		key   func() crypto.Signer
	}{{Suite0, newEd}, {Suite2, newP256}} {
		ik, rk := tc.key(), tc.key()
		ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{tc.suite}, PrivateKey: opaqueSigner{ik}, PeerPublic: rk.Public(), ConnectionID: []byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{tc.suite}, PrivateKey: opaqueSigner{rk}, PeerPublic: ik.Public(), ConnectionID: []byte{2}})
		if err != nil {
			t.Fatal(err)
		}
		if err := handshake(t, ini, res); err != nil {
			t.Fatalf("suite %d with an opaque crypto.Signer: %v", tc.suite, err)
		}
	}
}

// A v0.2.2-shaped config (PrivateKey + PeerPublic only) completes an
// RFC 9528 handshake with the peer pinned, and rejects any other key.
func TestConfigV022Shape(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, nil)
	if err := handshake(t, ini, res); err != nil {
		t.Fatal(err)
	}
	a, _ := ini.ExportOSCORE()
	b, _ := res.ExportOSCORE()
	if a == nil || b == nil || !bytes.Equal(a.MasterSecret, b.MasterSecret) {
		t.Fatal("OSCORE contexts differ")
	}
	_, stranger := edPair(t)
	ini, res = pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, _ *ResponderConfig) { ic.PeerPublic = stranger })
	if err := handshake(t, ini, res); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong pinned key: err = %v, want ErrAuthentication", err)
	}
}

// A default (RFC 9528) Initiator never completes with a pre-RFC peer,
// and is left with no OSCORE context.
func TestCompatDefaultRejectsLegacyPeer(t *testing.T) {
	iPriv, iPub := edPair(t)
	rPriv, rPub := edPair(t)
	ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, PeerPublic: iPub, ConnectionID: []byte{2}}, WithLegacyPreRFCProtocol())
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, ini, res); err == nil {
		t.Fatal("RFC 9528 Initiator completed a handshake with a pre-RFC Responder")
	}
	if c, err := ini.ExportOSCORE(); err == nil || c != nil {
		t.Fatalf("ExportOSCORE = %v, %v; want no context", c, err)
	}
}

// Two peers with WithLegacyPreRFCProtocol still interoperate. Byte-for-
// byte reproduction of v0.2.2 transcripts is TestGoldenLegacyReproducesV022.
func TestCompatLegacyPreRFCTranscript(t *testing.T) {
	iPriv, iPub := edPair(t)
	rPriv, rPub := edPair(t)
	ini, err := NewInitiator(InitiatorConfig{Suites: []CipherSuite{Suite0}, PrivateKey: iPriv, PeerPublic: rPub, ConnectionID: []byte{1}}, WithLegacyPreRFCProtocol())
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewResponder(ResponderConfig{Suites: []CipherSuite{Suite0}, PrivateKey: rPriv, PeerPublic: iPub, ConnectionID: []byte{2}}, WithLegacyPreRFCProtocol())
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, ini, res); err != nil {
		t.Fatal(err)
	}
	a, err := ini.ExportOSCORE()
	if err != nil {
		t.Fatal(err)
	}
	b, err := res.ExportOSCORE()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.MasterSecret, b.MasterSecret) {
		t.Fatal("legacy peers derived different OSCORE secrets")
	}
}

// WithLegacyPreRFCProtocol is Deprecated with a v0.5.0 removal floor.
func TestLegacySelectorDeprecated(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "config.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "WithLegacyPreRFCProtocol" {
			continue
		}
		doc := fn.Doc.Text()
		if !strings.Contains(doc, "Deprecated:") || !strings.Contains(doc, "v0.5.0") {
			t.Fatalf("doc lacks Deprecated/v0.5.0:\n%s", doc)
		}
		return
	}
	t.Fatal("WithLegacyPreRFCProtocol not found")
}

func TestConnectionID_Collision(t *testing.T) {
	ini, res := pair(t, []byte{7}, []byte{7}, nil)
	if err := handshake(t, ini, res); !errors.Is(err, ErrConnectionIDCollision) {
		t.Fatalf("err = %v, want ErrConnectionIDCollision", err)
	}
}

func TestEAD_UnknownCritical(t *testing.T) {
	ini, res := pair(t, []byte{1}, []byte{2}, func(ic *InitiatorConfig, _ *ResponderConfig) {
		ic.EAD1 = []EADItem{{Label: 42, Critical: true}}
	})
	err := handshake(t, ini, res)
	if !errors.Is(err, ErrCriticalEAD) || !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v, want ErrCriticalEAD + ErrAuthentication", err)
	}
}
