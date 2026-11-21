// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose_test

// goldenChanges lists golden vector IDs whose results may differ from
// v0.2.2, keyed to the proposal that changes them. Per proposal 034 only
// safety and contract defect fixes may change existing behavior. Add an
// entry in the same change that alters the behavior.
var goldenChanges = map[string]string{
	"cose/alg/35": "proposal 021 D17: HPKE algorithm String() no longer returns \"unknown\"",

	// Proposal 027 Phase 1.
	"cose/verify/protected-unsorted":            "proposal 027 H1: verify over the protected bytes as received (RFC 9052 §4.4)",
	"cose/unmarshal/sign1-bytes-header-label":   "proposal 027 H5: a bstr header label is ErrMalformed, not a panic",
	"cose/multi/verify-none-match":              "proposal 027 H6: VerifyMulti fails closed when no signature verifies",
	"cose/sign1/verify-nil-payload-after-empty": "proposal 027 H11: a nil (detached) payload is ErrMissingPayload, not the empty payload",
}
