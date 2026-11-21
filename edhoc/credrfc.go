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
	"fmt"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
)

// COSE key parameters (RFC 9053).
const (
	coseKeyKty  = 1
	coseKeyCrv  = -1
	coseKeyX    = -2
	coseKeyY    = -3
	ktyOKP      = 1
	ktyEC2      = 2
	crvP256     = 1
	crvP384     = 2
	crvX25519   = 4
	crvEd25519  = 6
	ccsClaimCnf = 8
	cnfCOSEKey  = 1
)

// credParty is what a party needs to build its own credential and
// resolve its peer's.
type credParty struct {
	signer       crypto.Signer
	dhKey        *ecdh.PrivateKey
	cred         *Credential
	peerPublic   crypto.PublicKey
	peerCred     *Credential
	cwtIssuerKey crypto.PublicKey
	peers        CredentialResolver
}

// ownCredential returns this party's CRED_x, ID_CRED_x and key: the
// configured Credential when it has Raw, a CWT sent by value for a v0.2
// CredentialCWT, or otherwise a CCS built from the authentication key
// and sent by value (kccs).
func (p credParty) ownCredential(authPub crypto.PublicKey) (*Credential, error) {
	c := p.cred
	switch {
	case c != nil && len(c.Raw) > 0:
		out := *c
		if out.IDCred.set() == 0 {
			out.IDCred = IDCred{KCCS: out.Raw}
		}
		if out.PublicKey == nil {
			out.PublicKey = authPub
		}
		return &out, nil
	case c != nil && c.Type == CredentialCWT && len(c.CWTBytes) > 0:
		return &Credential{Type: CredentialCWT, CWTBytes: c.CWTBytes, Raw: c.CWTBytes, IDCred: IDCred{KCWT: c.CWTBytes}, PublicKey: authPub}, nil
	}
	ccs, err := ccsFor(authPub)
	if err != nil {
		return nil, err
	}
	return &Credential{Raw: ccs, IDCred: IDCred{KCCS: ccs}, PublicKey: authPub}, nil
}

// ccsFor builds a CWT Claims Set {cnf: {COSE_Key: key}} (RFC 8747).
func ccsFor(pub crypto.PublicKey) ([]byte, error) {
	k, err := coseKeyOf(pub)
	if err != nil {
		return nil, err
	}
	cnf := cbor.MakeMap(cbor.MapEntry{Key: cbor.Uint(cnfCOSEKey), Value: k})
	return item(cbor.MakeMap(cbor.MapEntry{Key: cbor.Uint(ccsClaimCnf), Value: cnf})), nil
}

func intVal(n int64) cbor.Value {
	if n >= 0 {
		return cbor.Uint(uint64(n))
	}
	return cbor.NegInt(uint64(-1 - n))
}

// coseKeyOf returns pub as a COSE_Key, built with cose's key API so the
// encoding is the one cose produces and parses (deterministic: kty, crv,
// x, y). P-curve ECDH keys go through their ECDSA form. cose has no
// constructor for X25519 keys, so that OKP map is built here and then
// validated by cose.ParseKey.
func coseKeyOf(pub crypto.PublicKey) (cbor.Value, error) {
	if e, ok := pub.(*ecdh.PublicKey); ok {
		switch e.Curve() {
		case ecdh.X25519():
			return x25519COSEKey(e.Bytes())
		case ecdh.P256():
			p, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), e.Bytes())
			if err != nil {
				return cbor.Value{}, fmt.Errorf("%w: %w", ErrUnsupportedSuite, err)
			}
			pub = p
		case ecdh.P384():
			p, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), e.Bytes())
			if err != nil {
				return cbor.Value{}, fmt.Errorf("%w: %w", ErrUnsupportedSuite, err)
			}
			pub = p
		default:
			return cbor.Value{}, fmt.Errorf("%w: unsupported EC2 curve", ErrUnsupportedSuite)
		}
	}
	k, err := cose.NewKeyFromPublic(pub)
	if err != nil {
		return cbor.Value{}, fmt.Errorf("%w: cannot build a COSE_Key for %T: %w", ErrUnsupportedSuite, pub, err)
	}
	enc, err := k.MarshalCBOR()
	if err != nil {
		return cbor.Value{}, fmt.Errorf("%w: COSE_Key: %w", ErrUnsupportedSuite, err)
	}
	v, err := corecbor.NewDecoder(seqDecOpts...).Decode(enc)
	if err != nil {
		return cbor.Value{}, fmt.Errorf("%w: COSE_Key: %w", ErrUnsupportedSuite, err)
	}
	return v, nil
}

// x25519COSEKey builds an OKP X25519 COSE_Key and checks it with
// cose.ParseKey.
func x25519COSEKey(x []byte) (cbor.Value, error) {
	v := cbor.MakeMap(
		cbor.MapEntry{Key: intVal(coseKeyKty), Value: intVal(ktyOKP)},
		cbor.MapEntry{Key: intVal(coseKeyCrv), Value: intVal(crvX25519)},
		cbor.MapEntry{Key: intVal(coseKeyX), Value: cbor.Bytes(x)},
	)
	if _, err := cose.ParseKey(item(v)); err != nil {
		return cbor.Value{}, fmt.Errorf("%w: X25519 COSE_Key: %w", ErrUnsupportedSuite, err)
	}
	return v, nil
}

// publicFromCCS returns the key in a CCS's cnf claim.
func publicFromCCS(ccs []byte) (crypto.PublicKey, error) {
	v, err := corecbor.NewDecoder(seqDecOpts...).Decode(ccs)
	if err != nil {
		return nil, fmt.Errorf("%w: CCS: %w", ErrMessageFormat, err)
	}
	cnf, ok := mapGet(v, ccsClaimCnf)
	if !ok {
		return nil, fmt.Errorf("%w: CCS has no cnf claim", ErrAuthentication)
	}
	key, ok := mapGet(cnf, cnfCOSEKey)
	if !ok {
		return nil, fmt.Errorf("%w: cnf has no COSE_Key", ErrAuthentication)
	}
	return publicFromCOSEKey(key)
}

func mapGet(m cbor.Value, label int64) (cbor.Value, bool) {
	if m.Kind != cbor.KindMap {
		return cbor.Value{}, false
	}
	for _, e := range m.Pairs {
		if n, err := valueInt(e.Key, "label"); err == nil && n == label {
			return e.Value, true
		}
	}
	return cbor.Value{}, false
}

// publicFromCOSEKey returns the public key in COSE_Key k, parsed and
// validated (exact coordinate sizes, on-curve points) by cose.ParseKey.
func publicFromCOSEKey(k cbor.Value) (crypto.PublicKey, error) {
	if k.Kind != cbor.KindMap {
		return nil, fmt.Errorf("%w: COSE_Key must be a map", ErrAuthentication)
	}
	key, err := cose.ParseKey(item(k))
	if err != nil {
		return nil, fmt.Errorf("%w: COSE_Key: %w", ErrAuthentication, err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("%w: COSE_Key: %w", ErrAuthentication, err)
	}
	switch pub.(type) {
	case ed25519.PublicKey, *ecdh.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	}
	return nil, fmt.Errorf("%w: unsupported COSE_Key key type %T", ErrAuthentication, pub)
}

// samePublic reports whether two public keys are the same key,
// comparing ECDSA and ECDH forms of one P-curve key as equal.
func samePublic(a, b crypto.PublicKey) bool {
	if ea, ok := a.(*ecdsa.PublicKey); ok {
		if e, err := ea.ECDH(); err == nil {
			a = e
		}
	}
	if eb, ok := b.(*ecdsa.PublicKey); ok {
		if e, err := eb.ECDH(); err == nil {
			b = e
		}
	}
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// resolvePeer maps a received ID_CRED to the peer's credential: via
// Peers, a pinned PeerCredential, a CWT verified with CWTIssuerKey, or
// a CCS sent by value whose key is the pinned PeerPublic.
func (p credParty) resolvePeer(ctx context.Context, id IDCred) (*Credential, error) {
	unknown := fmt.Errorf("%w: unknown peer credential", ErrAuthentication)
	if p.peers != nil {
		c, err := p.peers.ResolveCredential(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("%w: resolving peer credential: %w", ErrAuthentication, err)
		}
		if c == nil || len(c.Raw) == 0 || c.PublicKey == nil {
			return nil, unknown
		}
		return c, nil
	}
	if pc := p.peerCred; pc != nil && len(pc.Raw) > 0 {
		match := (id.KCCS != nil && bytes.Equal(id.KCCS, pc.Raw)) || (id.KCWT != nil && bytes.Equal(id.KCWT, pc.Raw))
		if !match && pc.IDCred.set() == 1 {
			a, errA := pc.IDCred.full()
			b, errB := id.full()
			match = errA == nil && errB == nil && bytes.Equal(a, b)
		}
		if !match {
			return nil, unknown
		}
		out := *pc
		if out.PublicKey == nil {
			k, err := publicFromCCS(out.Raw)
			if err != nil {
				return nil, err
			}
			out.PublicKey = k
		}
		return &out, nil
	}
	if id.KCWT != nil {
		if p.cwtIssuerKey == nil {
			return nil, unknown
		}
		if pc := p.peerCred; pc != nil && pc.Type == CredentialCWT && len(pc.CWTBytes) > 0 && !bytes.Equal(pc.CWTBytes, id.KCWT) {
			return nil, unknown
		}
		k, err := extractPublicKeyFromCWT(id.KCWT, p.cwtIssuerKey)
		if err != nil {
			return nil, fmt.Errorf("%w: peer CWT: %w", ErrAuthentication, err)
		}
		if p.peerPublic != nil && !samePublic(k, p.peerPublic) {
			return nil, unknown
		}
		return &Credential{Type: CredentialCWT, CWTBytes: id.KCWT, Raw: id.KCWT, IDCred: id, PublicKey: k}, nil
	}
	if id.KCCS != nil && p.peerPublic != nil {
		k, err := publicFromCCS(id.KCCS)
		if err != nil {
			return nil, err
		}
		if !samePublic(k, p.peerPublic) {
			return nil, unknown
		}
		return &Credential{Raw: id.KCCS, IDCred: id, PublicKey: k}, nil
	}
	return nil, unknown
}
