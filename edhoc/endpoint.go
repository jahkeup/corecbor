// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"context"
	"fmt"
	"slices"
)

// Initiator runs the Initiator side of EDHOC (RFC 9528). It is not safe
// for concurrent use.
type Initiator struct {
	legacy *legacyInitiator
	s      *session
	suites []CipherSuite
}

// NewInitiator returns an Initiator. With no options it runs RFC 9528;
// WithLegacyPreRFCProtocol selects the deprecated v0.2 protocol.
func NewInitiator(cfg InitiatorConfig, opts ...Option) (*Initiator, error) {
	if applyOptions(opts).legacy {
		l, err := newLegacyInitiator(cfg)
		if err != nil {
			return nil, err
		}
		return &Initiator{legacy: l}, nil
	}
	if len(cfg.Suites) == 0 {
		return nil, fmt.Errorf("%w: no suites specified", ErrUnsupportedSuite)
	}
	if _, ok := lookupSuite(cfg.Suites[len(cfg.Suites)-1]); !ok {
		return nil, fmt.Errorf("%w: selected suite %d", ErrUnsupportedSuite, cfg.Suites[len(cfg.Suites)-1])
	}
	if !cfg.Method.valid() {
		return nil, fmt.Errorf("%w: unknown method %d", ErrStateViolation, cfg.Method)
	}
	if err := checkKeys(cfg.PrivateKey != nil || cfg.DHKey != nil,
		cfg.PeerPublic != nil || cfg.PeerCredential != nil || cfg.Peers != nil || cfg.CWTIssuerKey != nil); err != nil {
		return nil, err
	}
	if err := checkMethodKey(cfg.Method.initiatorSigns(), cfg.PrivateKey != nil, cfg.DHKey != nil); err != nil {
		return nil, err
	}
	s := &session{
		initiator: true,
		method:    cfg.Method,
		rand:      cfg.Rand,
		accept:    cfg.AcceptCriticalEAD,
		ownCID:    slices.Clone(cfg.ConnectionID),
		allocCID:  cfg.AllocateConnectionID,
		ownEAD:    map[int][]EADItem{1: cfg.EAD1, 3: cfg.EAD3},
		party: credParty{
			signer: cfg.PrivateKey, dhKey: cfg.DHKey, cred: cfg.Credential,
			peerPublic: cfg.PeerPublic, peerCred: cfg.PeerCredential,
			cwtIssuerKey: cfg.CWTIssuerKey, cwtValidator: cfg.CWTValidator, peers: cfg.Peers,
		},
	}
	return &Initiator{s: s, suites: slices.Clone(cfg.Suites)}, nil
}

// sess returns the RFC 9528 session, or nil for a zero-value or nil
// endpoint; session methods then return ErrStateViolation.
func (i *Initiator) sess() *session {
	if i == nil {
		return nil
	}
	return i.s
}

func (r *Responder) sess() *session {
	if r == nil {
		return nil
	}
	return r.s
}

// checkMethodKey fails fast when the method needs a key this party
// lacks: PrivateKey to sign, DHKey for static DH. A signing key is never
// used as a DH key (RFC 9528 §3.5.1).
func checkMethodKey(signs, hasSigner, hasDH bool) error {
	switch {
	case signs && !hasSigner:
		return fmt.Errorf("%w: the method authenticates this party with a signature and needs PrivateKey", ErrStateViolation)
	case !signs && !hasDH:
		return fmt.Errorf("%w: the method authenticates this party with static DH and needs DHKey; PrivateKey is a signing key and is not used for DH (RFC 9528 §3.5.1)", ErrStateViolation)
	}
	return nil
}

// checkKeys fails fast, as v0.2 did, when a party has no key to
// authenticate with or nothing to authenticate the peer against.
func checkKeys(own, peer bool) error {
	if !own || !peer {
		return fmt.Errorf("%w: missing keys", ErrStateViolation)
	}
	return nil
}

// CreateMessage1 returns message_1.
func (i *Initiator) CreateMessage1() ([]byte, error) {
	if i != nil && i.legacy != nil {
		return i.legacy.CreateMessage1()
	}
	if i.sess() == nil {
		return nil, errNoSession
	}
	return i.s.createMessage1(i.suites)
}

// ProcessMessage2 verifies message_2 and returns message_3. If the
// Responder sent an error message, the error is an *ErrorMessage
// (see RetrySuites for ERR_CODE 2). The resolver, if any, is called
// with context.Background().
func (i *Initiator) ProcessMessage2(msg2Raw []byte) ([]byte, error) {
	return i.ProcessMessage2Context(context.Background(), msg2Raw)
}

// ProcessMessage2Context is ProcessMessage2 with a context for the
// credential resolver.
func (i *Initiator) ProcessMessage2Context(ctx context.Context, msg2 []byte) ([]byte, error) {
	if i != nil && i.legacy != nil {
		return i.legacy.ProcessMessage2(msg2)
	}
	return i.sess().processMessage2(ctx, msg2)
}

// ProcessMessage4 verifies the optional message_4 (key confirmation).
// If the Responder sent an error message instead, the error is an
// *ErrorMessage.
func (i *Initiator) ProcessMessage4(msg4 []byte) error {
	if i != nil && i.legacy != nil {
		return i.legacy.ProcessMessage4(msg4)
	}
	return i.sess().processMessage4(msg4)
}

// Export is EDHOC_Exporter(label, context, length) (RFC 9528 §4.2.1),
// valid once the handshake is complete.
func (i *Initiator) Export(label int, context []byte, length int) ([]byte, error) {
	if i != nil && i.legacy != nil {
		return i.legacy.Export(label, context, length)
	}
	return i.sess().export(label, context, length)
}

// ExportOSCORE derives an OSCORE context with the default parameters
// (RFC 9528 Appendix A.1). The Initiator's Sender ID is C_R.
func (i *Initiator) ExportOSCORE() (*OSCOREContext, error) {
	if i != nil && i.legacy != nil {
		return i.legacy.ExportOSCORE()
	}
	return i.sess().oscore(OSCOREParams{})
}

// OSCORE derives an OSCORE context with explicit parameters.
func (i *Initiator) OSCORE(p OSCOREParams) (*OSCOREContext, error) {
	if i != nil && i.legacy != nil {
		return nil, fmt.Errorf("%w: not available with the legacy protocol", ErrStateViolation)
	}
	return i.sess().oscore(p)
}

// PRKOut returns a copy of PRK_out (RFC 9528 §4.1.3).
func (i *Initiator) PRKOut() ([]byte, error) {
	if i != nil && i.legacy != nil {
		return nil, fmt.Errorf("%w: not available with the legacy protocol", ErrStateViolation)
	}
	return i.sess().prkOutCopy()
}

// KeyUpdate derives a new PRK_out and PRK_exporter (RFC 9528
// Appendix H). Both peers must call it with the same context.
func (i *Initiator) KeyUpdate(context []byte) error {
	if i != nil && i.legacy != nil {
		return fmt.Errorf("%w: not available with the legacy protocol", ErrStateViolation)
	}
	return i.sess().keyUpdate(context)
}

// PeerEAD returns the EAD items received in the most recent message,
// once that message has been verified: EAD_2 after ProcessMessage2,
// EAD_4 after ProcessMessage4. It returns nil before then and after any
// failure.
func (i *Initiator) PeerEAD() []EADItem {
	if i.sess() == nil {
		return nil
	}
	return slices.Clone(i.sess().peerEAD)
}

// PeerCredential returns the Responder's credential once message_2 has
// been verified. It returns nil before then and after any failure,
// including a credential that resolved but whose signature or MAC did
// not verify.
func (i *Initiator) PeerCredential() *Credential {
	if i.sess() == nil {
		return nil
	}
	return i.sess().peerCred
}

// Close zeroizes the session's secrets. It is idempotent; later calls
// return ErrStateViolation.
func (i *Initiator) Close() {
	if i.sess() != nil {
		i.sess().close()
	}
}

// Responder runs the Responder side of EDHOC (RFC 9528). It is not safe
// for concurrent use.
type Responder struct {
	legacy *legacyResponder
	s      *session
	cfg    ResponderConfig
}

// NewResponder returns a Responder. With no options it runs RFC 9528;
// WithLegacyPreRFCProtocol selects the deprecated v0.2 protocol.
func NewResponder(cfg ResponderConfig, opts ...Option) (*Responder, error) {
	if applyOptions(opts).legacy {
		l, err := newLegacyResponder(cfg)
		if err != nil {
			return nil, err
		}
		return &Responder{legacy: l}, nil
	}
	if len(cfg.Suites) == 0 {
		return nil, fmt.Errorf("%w: no suites specified", ErrUnsupportedSuite)
	}
	if !cfg.Method.valid() {
		return nil, fmt.Errorf("%w: unknown method %d", ErrStateViolation, cfg.Method)
	}
	if err := checkKeys(cfg.PrivateKey != nil || cfg.DHKey != nil,
		cfg.PeerPublic != nil || cfg.PeerCredential != nil || cfg.Peers != nil || cfg.CWTIssuerKey != nil); err != nil {
		return nil, err
	}
	if !cfg.AnyMethod {
		if err := checkMethodKey(cfg.Method.responderSigns(), cfg.PrivateKey != nil, cfg.DHKey != nil); err != nil {
			return nil, err
		}
	}
	s := &session{
		method:   cfg.Method,
		rand:     cfg.Rand,
		accept:   cfg.AcceptCriticalEAD,
		ownCID:   slices.Clone(cfg.ConnectionID),
		allocCID: cfg.AllocateConnectionID,
		ownEAD:   map[int][]EADItem{2: cfg.EAD2, 4: cfg.EAD4},
		party: credParty{
			signer: cfg.PrivateKey, dhKey: cfg.DHKey, cred: cfg.Credential,
			peerPublic: cfg.PeerPublic, peerCred: cfg.PeerCredential,
			cwtIssuerKey: cfg.CWTIssuerKey, cwtValidator: cfg.CWTValidator, peers: cfg.Peers,
		},
	}
	return &Responder{s: s, cfg: cfg}, nil
}

// ProcessMessage1 processes message_1 and returns message_2. When the
// Responder can't continue (for example, an unsupported selected suite)
// the error is an *ErrorMessage; send its MarshalCBOR() to the peer.
func (r *Responder) ProcessMessage1(msg1Raw []byte) ([]byte, error) {
	if r != nil && r.legacy != nil {
		return r.legacy.ProcessMessage1(msg1Raw)
	}
	if r.sess() == nil {
		return nil, errNoSession
	}
	accept := func(m Method) bool { return r.cfg.AnyMethod || m == r.cfg.Method }
	return r.s.processMessage1(msg1Raw, r.cfg.Suites, accept)
}

// ProcessMessage3 verifies message_3, completing the handshake. If the
// Initiator sent an error message instead, the error is an
// *ErrorMessage. The resolver, if any, is called with
// context.Background().
func (r *Responder) ProcessMessage3(msg3Raw []byte) error {
	return r.ProcessMessage3Context(context.Background(), msg3Raw)
}

// ProcessMessage3Context is ProcessMessage3 with a context for the
// credential resolver.
func (r *Responder) ProcessMessage3Context(ctx context.Context, msg3 []byte) error {
	if r != nil && r.legacy != nil {
		return r.legacy.ProcessMessage3(msg3)
	}
	return r.sess().processMessage3(ctx, msg3)
}

// CreateMessage4 returns the optional message_4 (key confirmation).
func (r *Responder) CreateMessage4() ([]byte, error) {
	if r != nil && r.legacy != nil {
		return r.legacy.CreateMessage4()
	}
	return r.sess().createMessage4()
}

// Export is EDHOC_Exporter(label, context, length) (RFC 9528 §4.2.1).
func (r *Responder) Export(label int, context []byte, length int) ([]byte, error) {
	if r != nil && r.legacy != nil {
		return r.legacy.Export(label, context, length)
	}
	return r.sess().export(label, context, length)
}

// ExportOSCORE derives an OSCORE context with the default parameters
// (RFC 9528 Appendix A.1). The Responder's Sender ID is C_I.
func (r *Responder) ExportOSCORE() (*OSCOREContext, error) {
	if r != nil && r.legacy != nil {
		return r.legacy.ExportOSCORE()
	}
	return r.sess().oscore(OSCOREParams{})
}

// OSCORE derives an OSCORE context with explicit parameters.
func (r *Responder) OSCORE(p OSCOREParams) (*OSCOREContext, error) {
	if r != nil && r.legacy != nil {
		return nil, fmt.Errorf("%w: not available with the legacy protocol", ErrStateViolation)
	}
	return r.sess().oscore(p)
}

// PRKOut returns a copy of PRK_out.
func (r *Responder) PRKOut() ([]byte, error) {
	if r != nil && r.legacy != nil {
		return nil, fmt.Errorf("%w: not available with the legacy protocol", ErrStateViolation)
	}
	return r.sess().prkOutCopy()
}

// KeyUpdate derives a new PRK_out and PRK_exporter (RFC 9528
// Appendix H).
func (r *Responder) KeyUpdate(context []byte) error {
	if r != nil && r.legacy != nil {
		return fmt.Errorf("%w: not available with the legacy protocol", ErrStateViolation)
	}
	return r.sess().keyUpdate(context)
}

// PeerEAD returns the EAD items received in the most recent message:
// EAD_1 after ProcessMessage1, EAD_3 once message_3 has been verified.
// message_1 is not authenticated, so EAD_1 is unverified until
// ProcessMessage3 succeeds. It returns nil after any failure.
func (r *Responder) PeerEAD() []EADItem {
	if r.sess() == nil {
		return nil
	}
	return slices.Clone(r.sess().peerEAD)
}

// PeerCredential returns the Initiator's credential once message_3 has
// been verified. It returns nil before then and after any failure,
// including a credential that resolved but whose signature or MAC did
// not verify.
func (r *Responder) PeerCredential() *Credential {
	if r.sess() == nil {
		return nil
	}
	return r.sess().peerCred
}

// Close zeroizes the session's secrets. It is idempotent.
func (r *Responder) Close() {
	if r.sess() != nil {
		r.sess().close()
	}
}
