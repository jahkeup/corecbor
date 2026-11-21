// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc_test

// goldenChanges lists golden vector IDs whose results may differ from
// v0.2.2, keyed to the proposal that changes them. Per proposal 034 only
// safety and contract defect fixes may change existing behavior. Add an
// entry in the same change that alters the behavior.
//
// The v0.2.2 output for every ID below is still produced under
// WithLegacyPreRFCProtocol (TestGoldenLegacyReproducesV022).
var goldenChanges = map[string]string{
	// Proposal 033: RFC 9528 message layout (message_2 is one bstr with
	// C_R inside PLAINTEXT_2; message_3 is the AEAD ciphertext over the
	// Enc_structure with credential-bound MAC/signature).
	"edhoc/handshake/suite0/message2-shape": "proposal 033: RFC 9528 §5.3 message_2 layout",
	"edhoc/handshake/suite0/message3-shape": "proposal 033: RFC 9528 §5.4 message_3 contents",
	"edhoc/handshake/suite2/message2-shape": "proposal 033: RFC 9528 §5.3 message_2 layout",
	"edhoc/handshake/suite2/message3-shape": "proposal 033: RFC 9528 §5.4 message_3 contents",
	// Proposal 033: P-256 ephemeral keys are sent as the x-coordinate
	// (RFC 9528 §3.7).
	"edhoc/handshake/suite2/message1-shape": "proposal 033: RFC 9528 §3.7 P-256 x-coordinate G_X",
	// Proposal 033: OSCORE Sender ID is the peer's connection identifier
	// (RFC 9528 Appendix A.1); v0.2 had them swapped.
	"edhoc/handshake/suite0/oscore-context": "proposal 033: RFC 9528 Appendix A.1 sender/recipient IDs",
	"edhoc/handshake/suite2/oscore-context": "proposal 033: RFC 9528 Appendix A.1 sender/recipient IDs",
	// Proposal 033: cipher suite 1 is now supported (additive).
	"edhoc/config/initiator-unsupported-suite": "proposal 033: suite 1 is now supported",
	// Proposal 033: rejections are EDHOC error messages (*ErrorMessage,
	// RFC 9528 §6). They still match ErrUnsupportedSuite as in v0.2.2,
	// and additionally the new ErrPeerError.
	"edhoc/message1/method-1":                 "proposal 033: error message; still ErrUnsupportedSuite, plus ErrPeerError",
	"edhoc/message1/suite-unknown":            "proposal 033: error message; still ErrUnsupportedSuite, plus ErrPeerError",
	"edhoc/negotiation/responder-lacks-suite": "proposal 033: error message; still ErrUnsupportedSuite, plus ErrPeerError",
}
