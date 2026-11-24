// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/jahkeup/corecbor/cose"
)

// X509Policy authenticates a peer whose ID_CRED is an X.509 certificate
// chain by value (x5chain) or a certificate reference (x5t), RFC 9360.
type X509Policy struct {
	// Roots are the trust anchors the peer's chain must verify to. It is
	// required: the system roots are never used implicitly.
	Roots *x509.CertPool
	// Intermediates adds intermediate certificates to the ones the peer
	// sends in x5chain. Optional.
	Intermediates *x509.CertPool
	// KeyUsages are the acceptable extended key usages; empty means any
	// (RFC 9528 registers no EDHOC extended key usage). The keyUsage
	// extension is checked separately, against the method, by the
	// handshake: digitalSignature for signature authentication,
	// keyAgreement for static DH (RFC 9528 Appendix D.1).
	KeyUsages []x509.ExtKeyUsage
	// CurrentTime is the verification time; zero means now.
	CurrentTime time.Time
	// Certificates resolves an x5t reference to the referenced chain
	// (DER, leaf first). Without it, x5t credentials are rejected. The
	// leaf must hash to the x5t value.
	Certificates func(ctx context.Context, x5t X5T) ([][]byte, error)
	// VerifyPeer is called with the verified leaf to check the peer's
	// identity, such as its subject name (RFC 9528 Appendix D.2). An
	// error rejects the peer. It is required unless
	// AllowAnyPeerUnderRoots is set: without it every certificate
	// under Roots would be accepted as the peer.
	VerifyPeer func(leaf *x509.Certificate) error
	// AllowAnyPeerUnderRoots accepts any leaf that chains to Roots, with
	// no identity check, when VerifyPeer is nil. Set it only when every
	// certificate Roots can validate is an acceptable peer, such as a
	// private CA that issues only to this deployment's devices.
	AllowAnyPeerUnderRoots bool
}

// X509Resolver returns a CredentialResolver (for InitiatorConfig.Peers or
// ResponderConfig.Peers) that accepts x5chain and x5t credentials verified
// under p. The resulting CRED_x is the DER leaf certificate encoded as a
// CBOR byte string (RFC 9528 §3.5.2). Other ID_CRED types are rejected.
func X509Resolver(p X509Policy) CredentialResolver {
	return x509Resolver{p}
}

type x509Resolver struct{ p X509Policy }

func (r x509Resolver) ResolveCredential(ctx context.Context, id IDCred) (*Credential, error) {
	var chain [][]byte
	switch {
	case id.X5Chain != nil:
		chain = id.X5Chain
	case id.X5T != nil:
		if r.p.Certificates == nil {
			return nil, fmt.Errorf("%w: %w: x5t credential without a certificate lookup", ErrAuthentication, ErrUnknownCredential)
		}
		c, err := r.p.Certificates(ctx, *id.X5T)
		if err != nil {
			return nil, fmt.Errorf("%w: %w: x5t lookup: %w", ErrAuthentication, ErrUnknownCredential, err)
		}
		if len(c) == 0 || !id.X5T.Matches(c[0]) {
			return nil, fmt.Errorf("%w: x5t does not match the resolved certificate", ErrAuthentication)
		}
		chain = c
	default:
		return nil, fmt.Errorf("%w: not an X.509 credential", ErrAuthentication)
	}
	leaf, err := r.p.verify(chain)
	if err != nil {
		return nil, err
	}
	pub, err := certPublicKey(leaf)
	if err != nil {
		return nil, err
	}
	return &Credential{Raw: bstrItem(leaf.Raw), IDCred: id, PublicKey: pub}, nil
}

func (p X509Policy) verify(chain [][]byte) (*x509.Certificate, error) {
	if p.Roots == nil {
		return nil, fmt.Errorf("%w: X509Policy.Roots is required", ErrAuthentication)
	}
	if p.VerifyPeer == nil && !p.AllowAnyPeerUnderRoots {
		return nil, fmt.Errorf("%w: X509Policy has no VerifyPeer identity check; set VerifyPeer, or AllowAnyPeerUnderRoots to accept any certificate under Roots", ErrAuthentication)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty certificate chain", ErrAuthentication)
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %w", ErrAuthentication, i, err)
		}
		certs[i] = c
	}
	inter := x509.NewCertPool()
	if p.Intermediates != nil {
		inter = p.Intermediates.Clone()
	}
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	usages := p.KeyUsages
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         p.Roots,
		Intermediates: inter,
		CurrentTime:   p.CurrentTime,
		KeyUsages:     usages,
	}); err != nil {
		return nil, fmt.Errorf("%w: certificate chain: %w", ErrAuthentication, err)
	}
	if p.VerifyPeer != nil {
		if err := p.VerifyPeer(leaf); err != nil {
			return nil, fmt.Errorf("%w: peer certificate rejected: %w", ErrAuthentication, err)
		}
	}
	return leaf, nil
}

// certPublicKey returns the leaf's authentication key in the forms the
// handshake accepts: Ed25519 or ECDSA for signatures, ECDH (X25519 or a
// P-curve) for static DH.
func certPublicKey(c *x509.Certificate) (any, error) {
	switch k := c.PublicKey.(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey:
		return k, nil
	}
	return nil, fmt.Errorf("%w: unsupported certificate key type %T", ErrAuthentication, c.PublicKey)
}

// X509Credential builds this party's own credential from its certificate
// chain (DER, leaf first). With byReference, ID_CRED is an x5t
// (SHA-256/64) the peer resolves itself; otherwise the chain is sent by
// value in x5chain. CRED_x is the DER leaf encoded as a CBOR byte string.
func X509Credential(chain [][]byte, byReference bool) (*Credential, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty certificate chain", ErrMessageFormat)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("%w: leaf certificate: %w", ErrMessageFormat, err)
	}
	pub, err := certPublicKey(leaf)
	if err != nil {
		return nil, err
	}
	id := IDCred{X5Chain: slices.Clone(chain)}
	if byReference {
		sum := sha256.Sum256(leaf.Raw)
		id = IDCred{X5T: &X5T{Alg: cose.AlgSHA256_64, Hash: sum[:8]}}
	}
	return &Credential{Raw: bstrItem(leaf.Raw), IDCred: id, PublicKey: pub}, nil
}
