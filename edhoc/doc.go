// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package edhoc implements the EDHOC authenticated key exchange protocol
// (RFC 9528) for Suite 0 (X25519, EdDSA, AES-CCM-16-64-128, SHA-256).
//
// EDHOC establishes an OSCORE security context between two peers using a
// 3-message handshake. This implementation supports method 0 (signature/signature)
// with raw public key (RPK) credentials.
//
// Phase A implements the core protocol flow:
//   - Initiator creates Message 1 (METHOD, SUITES_I, G_X, C_I)
//   - Responder processes Message 1, returns Message 2 (G_Y, C_R, CIPHERTEXT_2)
//   - Initiator processes Message 2, returns Message 3 (CIPHERTEXT_3)
//   - Both parties export an OSCORE security context (Master Secret, Master Salt)
package edhoc
