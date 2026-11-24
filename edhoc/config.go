// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"io"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

// Method is the EDHOC authentication method (RFC 9528 §3.2): which
// party authenticates with a signature and which with a static DH key.
type Method int

const (
	MethodSigSig   Method = 0 // Initiator signature, Responder signature
	MethodSigStat  Method = 1 // Initiator signature, Responder static DH
	MethodStatSig  Method = 2 // Initiator static DH, Responder signature
	MethodStatStat Method = 3 // Initiator static DH, Responder static DH
)

func (m Method) valid() bool { return m >= MethodSigSig && m <= MethodStatStat }

// initiatorSigns reports whether the Initiator authenticates with a
// signature (methods 0 and 1); otherwise it uses static DH.
func (m Method) initiatorSigns() bool { return m == MethodSigSig || m == MethodSigStat }

// responderSigns reports whether the Responder authenticates with a
// signature (methods 0 and 2); otherwise it uses static DH.
func (m Method) responderSigns() bool { return m == MethodSigSig || m == MethodStatSig }

// CredentialResolver maps a received ID_CRED to a credential the
// application trusts. It MUST perform the application profile's
// validation (expiry, issuer, revocation); EDHOC does not.
type CredentialResolver interface {
	ResolveCredential(ctx context.Context, id IDCred) (*Credential, error)
}

// InitiatorConfig configures an Initiator. The v0.2 fields keep their
// names and types; new fields are appended and their zero values select
// method 0 with a pinned PeerPublic, as v0.2 did.
type InitiatorConfig struct {
	// Suites is SUITES_I as sent: the Initiator's cipher suites in
	// order of preference, truncated after the selected suite, which is
	// the LAST element (RFC 9528 §5.2.2). A single suite is sent as an
	// int. RetrySuites builds the next value after an error message.
	Suites []CipherSuite
	// PrivateKey signs for signature methods. Any crypto.Signer works
	// (ed25519 for EdDSA suites; *ecdsa.PrivateKey or a KMS signer for
	// ES256/ES384 suites).
	PrivateKey crypto.Signer
	// PeerPublic pins the peer's authentication key when neither Peers
	// nor PeerCredential is set; the peer must then send its credential
	// by value (kccs) containing this key.
	PeerPublic crypto.PublicKey
	// ConnectionID is C_I, which is also this party's OSCORE Recipient
	// ID. When nil, AllocateConnectionID chooses it.
	ConnectionID []byte
	// AllocateConnectionID chooses this party's connection identifier
	// when ConnectionID is nil. It is called once, with the peer's
	// identifier (nil for the Initiator), and must return one that no
	// current EDHOC session uses as this party's identifier and no
	// current OSCORE Security Context uses as its Recipient ID (RFC
	// 9668 §4.1.1, §4.1.2); back it with the application's session and
	// OSCORE context tables. A result equal to the peer's identifier is
	// rejected with ErrConnectionIDCollision.
	//
	// When nil, a random identifier is drawn, preferring the 48 sent as
	// one-byte CBOR integers, that avoids the peer's identifier and
	// every identifier held by an endpoint in this process that has not
	// been closed, failed or garbage collected. That is all it can know
	// about: it does not see OSCORE contexts that outlive their
	// endpoint, or other processes. Callers running many sessions, or
	// keeping OSCORE contexts after Close, must supply an allocator.
	AllocateConnectionID func(peer ConnectionID) (ConnectionID, error)

	Credential     *Credential
	PeerCredential *Credential
	// CWTIssuerKey verifies a CWT credential the peer sends by value
	// (kcwt). It never falls back to PeerPublic.
	CWTIssuerKey crypto.PublicKey
	// CWTValidator validates the claims of a CWT the peer sends by value
	// (kcwt), after its signature verifies. When nil, cwt.NewValidator()
	// is used: exp required, nbf and exp checked against the current
	// time with a 60-second leeway. Set it to require an audience or
	// issuer, or to supply a clock. A CCS the peer sends by value
	// (kccs) has no issuer signature; when it carries exp, nbf or iat
	// they are checked with this validator's clock, leeway and
	// RejectFutureIssuedAt, but none is required. Credentials returned
	// by Peers are the resolver's to validate.
	CWTValidator *cwt.Validator

	// Method is the authentication method (default MethodSigSig).
	Method Method
	// DHKey is the static DH key for methods where this party
	// authenticates with static DH; those methods require it. PrivateKey
	// is never used in its place: RFC 9528 §3.5.1 and RFC 9052 §12
	// strongly discourage one key for both signatures and DH.
	DHKey *ecdh.PrivateKey
	// Peers resolves the peer's ID_CRED; it takes precedence over
	// PeerCredential and PeerPublic.
	Peers CredentialResolver
	// EAD1 and EAD3 are sent in message_1 and message_3.
	EAD1, EAD3 []EADItem
	// AcceptCriticalEAD decides whether a received critical EAD item is
	// understood. When nil, any critical item aborts (RFC 9528 §3.8).
	AcceptCriticalEAD func(EADItem) bool
	// Rand overrides crypto/rand for ephemeral keys and connection IDs
	// (deterministic tests, RFC 9529).
	Rand io.Reader
}

// ResponderConfig configures a Responder; fields mirror InitiatorConfig.
type ResponderConfig struct {
	// Suites are the cipher suites the Responder supports, in order of
	// preference. They are sent as SUITES_R in an error message when
	// the Initiator's selected suite is not acceptable.
	Suites     []CipherSuite
	PrivateKey crypto.Signer
	PeerPublic crypto.PublicKey
	// ConnectionID is C_R, which is also this party's OSCORE Recipient
	// ID. When nil, AllocateConnectionID chooses it.
	ConnectionID []byte
	// AllocateConnectionID is as for InitiatorConfig; it is called
	// with C_I from message_1.
	AllocateConnectionID func(peer ConnectionID) (ConnectionID, error)

	Credential     *Credential
	PeerCredential *Credential
	CWTIssuerKey   crypto.PublicKey
	// CWTValidator is as for InitiatorConfig.
	CWTValidator *cwt.Validator

	// Method is the only authentication method accepted unless
	// AnyMethod is set. The zero value accepts MethodSigSig, as v0.2
	// did.
	Method Method
	// AnyMethod accepts whichever method the Initiator selects that
	// this configuration can serve.
	AnyMethod bool
	DHKey     *ecdh.PrivateKey
	Peers     CredentialResolver
	// EAD2 and EAD4 are sent in message_2 and message_4.
	EAD2, EAD4        []EADItem
	AcceptCriticalEAD func(EADItem) bool
	Rand              io.Reader
}

// Option configures an Initiator or Responder.
type Option func(*options)

type options struct {
	legacy bool
}

// WithLegacyPreRFCProtocol runs the pre-RFC key schedule, message
// layout and OSCORE export that corecbor <= v0.2 implemented. It
// interoperates ONLY with peers running corecbor <= v0.2 and gives none
// of RFC 9528's credential-binding guarantees. It exists so deployed
// v0.2 fleets can upgrade both ends in stages. The v0.2 config fields
// (Suites, PrivateKey, PeerPublic, ConnectionID, Credential,
// PeerCredential, CWTIssuerKey) are used exactly as v0.2.2 used them;
// the new fields are ignored.
//
// Deprecated: non-interoperable and missing identity binding. Removed
// no earlier than v0.32.0. Not part of any CompatV02 bundle.
func WithLegacyPreRFCProtocol() Option {
	return func(o *options) { o.legacy = true }
}

func applyOptions(opts []Option) options {
	var o options
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	return o
}

// OSCOREContext is the input to an OSCORE security context derived
// from a completed EDHOC session (RFC 9528 Appendix A.1).
type OSCOREContext struct {
	MasterSecret []byte
	MasterSalt   []byte
	// SenderID is the peer's connection identifier.
	SenderID []byte
	// RecipientID is this party's connection identifier.
	RecipientID []byte
	// AEAD and HKDF are the OSCORE algorithms: the selected suite's
	// application AEAD, and HKDF for its application hash (0 when no
	// COSE identifier is registered for that hash).
	AEAD cose.Algorithm
	HKDF cose.Algorithm
}

// OSCOREParams overrides the OSCORE derivation defaults.
type OSCOREParams struct {
	// MasterSecretLen defaults to the application AEAD key length.
	MasterSecretLen int
	// MasterSaltLen defaults to 8.
	MasterSaltLen int
}
