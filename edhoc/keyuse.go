// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/cose"
)

// keyUse is what an authentication key may be used for: signature
// authentication, static DH authentication, or both when nothing in the
// key or its credential says (RFC 9528 §3.5.1, Appendix D.1).
type keyUse struct {
	sign, dh bool
	// why names the restriction, for errors. After and, noSign and noDH
	// name what rules out each use.
	why, noSign, noDH string
}

var anyUse = keyUse{sign: true, dh: true}

// and combines two restrictions, keeping the first reason each use is
// ruled out.
func (u keyUse) and(v keyUse) keyUse {
	out := keyUse{sign: u.sign && v.sign, dh: u.dh && v.dh}
	for _, w := range []keyUse{u, v} {
		if out.noSign == "" && !w.sign {
			out.noSign = w.reason(true)
		}
		if out.noDH == "" && !w.dh {
			out.noDH = w.reason(false)
		}
	}
	return out
}

// reason names what rules out a signature (signs) or DH use.
func (u keyUse) reason(signs bool) string {
	if signs && u.noSign != "" {
		return u.noSign
	}
	if !signs && u.noDH != "" {
		return u.noDH
	}
	return u.why
}

func (u keyUse) allows(signs bool) bool {
	if signs {
		return u.sign
	}
	return u.dh
}

// COSE algorithms (RFC 9053, RFC 9864) that name a signature or a key
// agreement use of a COSE_Key.
var (
	coseSignatureAlgs = map[cose.Algorithm]bool{
		-7: true, -35: true, -36: true, // ES256, ES384, ES512
		-8: true, -19: true, -53: true, // EdDSA, Ed25519, Ed448
		-9: true, -51: true, -52: true, // ESP256, ESP384, ESP512
	}
	coseKeyAgreementAlgs = map[cose.Algorithm]bool{
		-25: true, -26: true, // ECDH-ES + HKDF-256/512
		-27: true, -28: true, // ECDH-SS + HKDF-256/512
		-29: true, -30: true, -31: true, // ECDH-ES + A128KW/A192KW/A256KW
		-32: true, -33: true, -34: true, // ECDH-SS + A128KW/A192KW/A256KW
	}
)

// useOfPublic is what the key type allows: Ed25519 keys only sign,
// X25519 and other ecdh keys only agree. A P-curve key is ambiguous in
// Go and COSE (one EC2 key type serves both), so the credential decides.
func useOfPublic(pub any) keyUse {
	switch pub.(type) {
	case ed25519.PublicKey:
		return keyUse{sign: true, why: "an Ed25519 key"}
	case *ecdh.PublicKey:
		return keyUse{dh: true, why: "an ECDH key"}
	}
	return anyUse
}

// useOfCOSEKey reads a COSE_Key's alg and key_ops (RFC 9052 §7.1).
func useOfCOSEKey(k *cose.Key) keyUse {
	u := anyUse
	if alg, ok := k.Algorithm(); ok {
		switch {
		case coseSignatureAlgs[alg]:
			u = keyUse{sign: true, why: fmt.Sprintf("COSE_Key alg %d is a signature algorithm", alg)}
		case coseKeyAgreementAlgs[alg]:
			u = keyUse{dh: true, why: fmt.Sprintf("COSE_Key alg %d is a key agreement algorithm", alg)}
		default:
			return keyUse{why: fmt.Sprintf("COSE_Key alg %d is neither a signature nor a key agreement algorithm", alg)}
		}
	}
	ops := keyUse{
		sign: k.Permits(cose.KeyOpSign) || k.Permits(cose.KeyOpVerify),
		dh:   k.Permits(cose.KeyOpDeriveKey) || k.Permits(cose.KeyOpDeriveBits),
		why:  "COSE_Key key_ops",
	}
	return u.and(ops)
}

// useOfCert reads an X.509 keyUsage extension: digitalSignature for
// signature keys, keyAgreement for static DH keys (RFC 9528 Appendix
// D.1, RFC 5280 §4.2.1.3). Without the extension the key is
// unrestricted.
func useOfCert(c *x509.Certificate) keyUse {
	if c.KeyUsage == 0 {
		return anyUse
	}
	return keyUse{
		sign: c.KeyUsage&x509.KeyUsageDigitalSignature != 0,
		dh:   c.KeyUsage&x509.KeyUsageKeyAgreement != 0,
		why:  "certificate keyUsage",
	}
}

// credentialUse is what a credential's authentication key may be used
// for, from the key type and, where the credential says, the COSE_Key in
// a CCS or CWT cnf claim or the X.509 keyUsage of a certificate.
func credentialUse(c *Credential) keyUse {
	u := useOfPublic(c.PublicKey)
	switch {
	case c.coseKey != nil:
		return u.and(useOfCOSEKey(c.coseKey))
	case len(c.Raw) == 0:
		return u
	}
	v, err := corecbor.NewDecoder(seqDecOpts...).Decode(c.Raw)
	if err != nil {
		return u
	}
	switch v.Kind {
	case cbor.KindMap: // CCS
		if cnf, ok := mapGet(v, ccsClaimCnf); ok {
			if kv, ok := mapGet(cnf, cnfCOSEKey); ok {
				if k, err := cose.ParseKey(item(kv)); err == nil {
					return u.and(useOfCOSEKey(k))
				}
			}
		}
	case cbor.KindBytes: // X.509 certificate
		if cert, err := x509.ParseCertificate(v.Bstr); err == nil {
			return u.and(useOfCert(cert))
		}
	}
	return u
}

// checkUse reports whether credential c's key may authenticate with a
// signature (signs) or static DH, naming the restriction otherwise.
func checkUse(c *Credential, signs bool) error {
	u := credentialUse(c)
	if u.allows(signs) {
		return nil
	}
	want := "static DH"
	if signs {
		want = "signature"
	}
	return fmt.Errorf("key is not usable for %s authentication: %s (RFC 9528 §3.5.1)", want, u.reason(signs))
}
