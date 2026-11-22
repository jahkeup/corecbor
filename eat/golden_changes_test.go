// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat_test

// goldenChanges lists golden vector IDs whose results may differ from
// v0.2.2, keyed to the proposal that changes them. Per proposal 034 only
// safety and contract defect fixes may change existing behavior. Add an
// entry in the same change that alters the behavior.
var goldenChanges = map[string]string{
	// Proposal 032: claim keys follow RFC 9711 / the IANA CWT registry
	// (contract defect: the package documents RFC 9711). The v0.2.2
	// bytes are reproduced under WithLegacyDraftClaimKeys
	// (TestGoldenLegacyReproducesV022).
	"eat/encode/uptime":                    "proposal 032: uptime is RFC 9711 claim 261 (v0.2.2 used draft key 266)",
	"eat/encode/sw-components":             "proposal 032: software components are RFC 9783 claim 2399 (v0.2.2 used 267, RFC 9711 bootcount)",
	"eat/encode/submods-inline":            "proposal 032: submods is RFC 9711 claim 266 (v0.2.2 used 268, RFC 9711 bootseed)",
	"eat/encode/submods-token":             "proposal 032: submods is RFC 9711 claim 266 (v0.2.2 used 268, RFC 9711 bootseed)",
	"eat/encode/security-level":            "proposal 032: security-level is not an RFC 9711 claim; encoding it needs WithLegacyDraftClaimKeys (ErrClaimNumbering)",
	"eat/decode/roundtrip-uptime-seclevel": "proposal 032: security-level is not an RFC 9711 claim; encoding it needs WithLegacyDraftClaimKeys (ErrClaimNumbering)",
	"eat/decode/rfc9711-uptime-261":        "proposal 032: RFC 9711 claim 261 is uptime (v0.2.2 read it as security level)",
	"eat/decode/rfc9711-submods-266":       "proposal 032: RFC 9711 claim 266 is submods (v0.2.2 read it as uptime and failed)",
	"eat/decode/rfc9711-bootcount-267":     "proposal 032: RFC 9711 claim 267 is bootcount (v0.2.2 read it as sw-components and failed)",
	"eat/decode/rfc9711-bootseed-268":      "proposal 032: RFC 9711 claim 268 is bootseed (v0.2.2 read it as submods and failed)",
	"eat/decode/profile-oid-bstr":          "proposal 032: eat_profile may be an OID (RFC 9711 §4.3.2); v0.2.2 rejected the bstr form",

	// Proposal 032 safety defect: nested-token submodules fail closed
	// without a verifier (v0.2.2 decoded them unverified and trusted them).
	"eat/appraise/submod-token-no-verifier": "proposal 032: nested-token submodule without a verifier fails closed (ErrSubmodUnverified)",
}
