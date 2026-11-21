// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"fmt"
	"slices"

	"github.com/jahkeup/corecbor/wire"
)

// EDHOC over CoAP (RFC 9528 Appendix A.2) and the combined EDHOC +
// OSCORE request (RFC 9668). These helpers frame payloads only; they do
// not depend on a CoAP stack.
const (
	// WellKnownPath is the default EDHOC resource (RFC 9528 §10.7).
	WellKnownPath = "/.well-known/edhoc"
	// MediaTypeEDHOC is an EDHOC message (RFC 9528 §10.8.1).
	MediaTypeEDHOC = "application/edhoc+cbor-seq"
	// MediaTypeCIDEDHOC is an EDHOC message prepended with a
	// connection identifier or true (RFC 9528 §10.8.2).
	MediaTypeCIDEDHOC = "application/cid-edhoc+cbor-seq"
	// ContentFormatEDHOC and ContentFormatCIDEDHOC are the CoAP
	// Content-Format IDs of those media types (RFC 9528 §10.9).
	ContentFormatEDHOC    = 64
	ContentFormatCIDEDHOC = 65
	// CoAPOptionEDHOC is the EDHOC option number (RFC 9668 §3.1). It is
	// critical, always empty, and signals a combined EDHOC + OSCORE
	// request.
	CoAPOptionEDHOC = 21
)

// cborTrue is the CBOR simple value true, prepended to message_1.
const cborTrue = 0xf5

// CoAPMessage1 prepends message_1 with the CBOR simple value true, which
// marks a new EDHOC session in the forward message flow (RFC 9528
// Appendix A.2). The result has media type MediaTypeCIDEDHOC.
func CoAPMessage1(msg1 []byte) []byte {
	return append([]byte{cborTrue}, msg1...)
}

// CoAPMessageWithCID prepends msg with the CBOR encoding of the
// connection identifier the server selected (RFC 9528 Appendix A.2): C_R
// in the forward message flow (message_3, message_4, error messages), C_I
// in the reverse flow. The result has media type MediaTypeCIDEDHOC.
func CoAPMessageWithCID(cid ConnectionID, msg []byte) []byte {
	return append(encodeCID(cid), msg...)
}

// SplitCoAPPrefix parses the identifier a client prepended to a request
// payload (RFC 9528 Appendix A.2). For message_1 it returns isMessage1
// and no identifier; otherwise it returns the connection identifier to
// dispatch on. rest is the EDHOC message that follows. An empty payload
// (the reverse flow's trigger) or a prefix that is neither true nor a
// connection identifier is an error wrapping ErrMessageFormat.
func SplitCoAPPrefix(payload []byte) (cid ConnectionID, isMessage1 bool, rest []byte, err error) {
	if len(payload) == 0 {
		return nil, false, nil, fmt.Errorf("%w: empty CoAP payload has no EDHOC prefix", ErrMessageFormat)
	}
	if payload[0] == cborTrue {
		return nil, true, payload[1:], nil
	}
	if isOneByteInt(payload[0]) {
		return ConnectionID{payload[0]}, false, payload[1:], nil
	}
	h := wire.ParseHead(payload)
	// Connection identifiers are encoded deterministically (RFC 9528
	// §3.3.2): a definite, shortest-form byte string head.
	if h.N == 0 || h.Major != wire.MajorBytes || h.AI > wire.AI8Bytes || !h.IsShortest() {
		return nil, false, nil, fmt.Errorf("%w: CoAP prefix must be true or a connection identifier", ErrMessageFormat)
	}
	if h.Arg > uint64(len(payload)-h.N) {
		return nil, false, nil, fmt.Errorf("%w: truncated connection identifier", ErrMessageFormat)
	}
	end := h.N + int(h.Arg)
	return ConnectionID(slices.Clone(payload[h.N:end])), false, payload[end:], nil
}

// CombinedPayload builds the payload of an EDHOC + OSCORE request,
// COMB_PAYLOAD = EDHOC_MSG_3 | OSCORE_PAYLOAD (RFC 9668 §3.2.1, Step 3).
// msg3 must be exactly one CBOR byte string (CIPHERTEXT_3); C_R travels
// as the OSCORE 'kid', not in the payload. The request also carries the
// empty EDHOC option (CoAPOptionEDHOC).
func CombinedPayload(msg3, oscorePayload []byte) ([]byte, error) {
	n, err := byteStringLen(msg3)
	if err != nil {
		return nil, err
	}
	if n != len(msg3) {
		return nil, fmt.Errorf("%w: message_3 must be a single CBOR byte string", ErrMessageFormat)
	}
	if len(oscorePayload) == 0 {
		return nil, fmt.Errorf("%w: empty OSCORE payload", ErrMessageFormat)
	}
	return append(slices.Clone(msg3), oscorePayload...), nil
}

// SplitCombinedPayload splits the payload of an EDHOC + OSCORE request
// into EDHOC message_3 and the OSCORE ciphertext (RFC 9668 §3.3.1, Steps
// 1, 2 and 6). A payload not in that format is an error wrapping
// ErrMessageFormat; the server then answers 4.00 (Bad Request). The
// connection identifier C_R is the 'kid' of the request's OSCORE option:
// ConnectionID(kid).
func SplitCombinedPayload(payload []byte) (msg3, oscorePayload []byte, err error) {
	n, err := byteStringLen(payload)
	if err != nil {
		return nil, nil, err
	}
	if n == len(payload) {
		return nil, nil, fmt.Errorf("%w: combined payload has no OSCORE ciphertext", ErrMessageFormat)
	}
	return payload[:n], payload[n:], nil
}

// byteStringLen returns the encoded length of the definite-length CBOR
// byte string at the start of b.
func byteStringLen(b []byte) (int, error) {
	h := wire.ParseHead(b)
	if h.N == 0 || h.Major != wire.MajorBytes || h.AI > wire.AI8Bytes {
		return 0, fmt.Errorf("%w: expected a CBOR byte string (message_3)", ErrMessageFormat)
	}
	if h.Arg > uint64(len(b)-h.N) {
		return 0, fmt.Errorf("%w: truncated message_3", ErrMessageFormat)
	}
	return h.N + int(h.Arg), nil
}

// ConnectionID returns this Initiator's connection identifier C_I, or
// nil before CreateMessage1 when it is chosen automatically. The
// Responder prepends it in the reverse message flow; it is also the
// Initiator's OSCORE Recipient ID.
func (i *Initiator) ConnectionID() ConnectionID {
	if i.legacy != nil {
		return slices.Clone(ConnectionID(i.legacy.connectionID))
	}
	return slices.Clone(ConnectionID(i.s.ownCID))
}

// PeerConnectionID returns the Responder's connection identifier C_R
// once message_2 has been processed, or nil. In the forward message flow
// the Initiator prepends it to message_3 (CoAPMessageWithCID) or sends it
// as the OSCORE 'kid' of a combined request.
func (i *Initiator) PeerConnectionID() ConnectionID {
	if i.legacy != nil {
		return slices.Clone(ConnectionID(i.legacy.peerConnID))
	}
	return slices.Clone(ConnectionID(i.s.peerCID))
}

// ConnectionID returns this Responder's connection identifier C_R once
// message_2 has been created, or nil. A CoAP server dispatches later
// requests to this session by it (SplitCoAPPrefix, or the OSCORE 'kid'
// of a combined request).
func (r *Responder) ConnectionID() ConnectionID {
	if r.legacy != nil {
		return slices.Clone(ConnectionID(r.legacy.connectionID))
	}
	return slices.Clone(ConnectionID(r.s.ownCID))
}

// PeerConnectionID returns the Initiator's connection identifier C_I once
// message_1 has been processed, or nil.
func (r *Responder) PeerConnectionID() ConnectionID {
	if r.legacy != nil {
		return slices.Clone(ConnectionID(r.legacy.peerConnID))
	}
	return slices.Clone(ConnectionID(r.s.peerCID))
}
