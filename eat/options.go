// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

// Option configures EAT encoding, decoding, signing and verification.
type Option func(*config)

type config struct {
	num numbering
}

func newConfig(opts []Option) config {
	c := config{num: rfcNumbering}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// WithLegacyDraftClaimKeys reads and writes the draft-era claim
// numbering used by corecbor <= v0.2 instead of RFC 9711's: 261 =
// security level, 266 = uptime, 267 = software components, 268 =
// submods. It applies to every claim in the token, including inline
// submodules; the numberings are never mixed or guessed between. Claims
// that exist only in RFC 9711 are not decoded (they stay in
// PrivateClaims) and cannot be encoded (ErrClaimNumbering).
//
// Deprecated: the draft-era keys conflict with RFC 9711 and the IANA
// CWT registry. Retained for reading and re-issuing tokens produced by
// corecbor <= v0.2. Removed no earlier than v0.32.0.
func WithLegacyDraftClaimKeys() Option {
	return func(c *config) { c.num = legacyNumbering }
}

// CompatV02 applies every selector needed to reproduce v0.2.x eat
// behavior: WithLegacyDraftClaimKeys.
//
// Deprecated: migrate to explicit selectors; removed no earlier than v0.32.0.
func CompatV02() Option {
	return WithLegacyDraftClaimKeys()
}
