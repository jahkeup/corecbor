// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

// goldenChanges lists golden vector IDs whose results may differ from
// v0.2.2, keyed to the proposal that changes them. Per proposal 034 only
// safety and contract defect fixes may change existing behavior. Add an
// entry in the same change that alters the behavior.
var goldenChanges = map[string]string{
	"cwt/validate/negative-leeway": "proposal 021 D17: negative Leeway returns ErrInvalidValidator instead of tightening the window",

	// v0.2.2 emitted a map with key 1 twice (not valid CBOR, RFC 8949
	// §5.6). 031 rejects the conflicting claim in Encode itself.
	"cwt/encode/private-shadows-iss": "proposal 031 (and 021 D15): a claim set twice with different values returns ErrMalformedClaims",

	// Proposal 031.
	"cwt/decode/aud-array":              "proposal 031: aud arrays (RFC 9200 §5.10.1) decode into Audiences; Audience stays the single-string form",
	"cwt/decode/exp-uint-max":           "proposal 031: NumericDate outside the int64 range is rejected instead of wrapping to a past time",
	"cwt/decode/duplicate-exp":          "proposal 031: duplicate claims are rejected (RFC 8392 §7.2); DecodeOptions.AllowDuplicateClaims restores last-wins",
	"cwt/decode/private-bytes-key":      "proposal 031: a byte-string claim key no longer panics; 037 W15 rejects it (claim keys are integers or text, RFC 8392 §3)",
	"cwt/decode/private-array-key":      "proposal 031: an array claim key no longer panics; 037 W15 rejects it (claim keys are integers or text, RFC 8392 §3)",
	"cwt/decode/negint-key-aliases-iss": "proposal 031: an integer key outside int64 no longer wraps onto iss; it is a private claim",
	"cwt/validate/exp-equals-now":       "proposal 031: a token is rejected on or after exp (RFC 8392 §3.1.4, RFC 7519 §4.1.4)",
	"cwt/sign/verify-tag61-wrapped":     "proposal 031: an outer CWT tag 61 is accepted (RFC 8392 §6)",

	// Proposal 037 W1 (safety defect, 034): fail-open audience check.
	"cwt/validate/audience-unset-token-has-aud": "proposal 037 W1: a token carrying aud is rejected unless the Validator accepts one of its audiences (RFC 7519 §4.1.3); IgnoreAudience opts out",
}
