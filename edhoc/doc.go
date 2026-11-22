// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package edhoc implements the EDHOC authenticated key exchange
// (RFC 9528).
//
// The protocol core reproduces the RFC 9529 traces byte-for-byte.
//
// EDHOC is a three-message key exchange (an optional fourth confirms
// keys) between an Initiator and a Responder:
//
//	Initiator                         Responder
//	CreateMessage1      ── msg1 ──►   ProcessMessage1
//	ProcessMessage2     ◄── msg2 ──
//	                    ── msg3 ──►   ProcessMessage3
//	ProcessMessage4     ◄── msg4 ──   CreateMessage4 (optional)
//
// Afterwards both sides call ExportOSCORE (RFC 9528 Appendix A.1) or
// Export (EDHOC_Exporter) for application keys, and Close to zeroize
// secrets. Any error is terminal for the session.
//
// All four authentication methods (InitiatorConfig.Method) and cipher
// suites 0–6 and 24 are supported. A party authenticates with a
// crypto.Signer (signature methods) or a static DH key (DHKey). The
// peer's credential comes from Peers (a CredentialResolver), a pinned
// PeerCredential, or a pinned PeerPublic matched against a credential
// sent by value. SUITES_I lists the Initiator's preferences with the
// selected suite last; after an ERR_CODE 2 error message, RetrySuites
// builds the next SUITES_I.
//
// WithLegacyPreRFCProtocol selects the deprecated pre-RFC protocol of
// corecbor v0.2, for upgrading deployed v0.2 peers in stages only.
package edhoc
