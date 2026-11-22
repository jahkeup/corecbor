// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

// Registered EAT claim keys (RFC 9711 §10.2, IANA "CBOR Web Token (CWT)
// Claims" registry).
const (
	ClaimNonce        int64 = 10
	ClaimUEID         int64 = 256
	ClaimSUEIDs       int64 = 257
	ClaimOEMID        int64 = 258
	ClaimHWModel      int64 = 259
	ClaimHWVersion    int64 = 260
	ClaimUptime       int64 = 261
	ClaimOEMBoot      int64 = 262
	ClaimDbgStat      int64 = 263
	ClaimLocation     int64 = 264
	ClaimProfile      int64 = 265
	ClaimSubmods      int64 = 266
	ClaimBootCount    int64 = 267
	ClaimBootSeed     int64 = 268
	ClaimDLOAs        int64 = 269
	ClaimSWName       int64 = 270
	ClaimSWVersion    int64 = 271
	ClaimManifests    int64 = 272
	ClaimMeasurements int64 = 273
	ClaimMeasRes      int64 = 274
	ClaimIntUse       int64 = 275

	// ClaimPSASoftwareComponents is RFC 9783's psa-software-components,
	// the claim Claims.SWComponents maps to.
	ClaimPSASoftwareComponents int64 = 2399
)

// TagDetachedEATBundle is the CBOR tag of a detached EAT bundle (RFC 9711 §5).
const TagDetachedEATBundle uint64 = 602

// EAT media types (RFC 9782 §6.1–6.6).
const (
	MediaTypeEATCWT      = "application/eat+cwt"
	MediaTypeEATJWT      = "application/eat+jwt"
	MediaTypeEATBundle   = "application/eat-bun+cbor"
	MediaTypeEATBundleJS = "application/eat-bun+json"
	MediaTypeEATUCSCBOR  = "application/eat-ucs+cbor"
	MediaTypeEATUCSJSON  = "application/eat-ucs+json"
)

// CoAP Content-Format numbers for the EAT media types (RFC 9782 §6.9).
const (
	ContentFormatEATCWT      uint16 = 263
	ContentFormatEATJWT      uint16 = 264
	ContentFormatEATBundle   uint16 = 265
	ContentFormatEATBundleJS uint16 = 266
	ContentFormatEATUCSCBOR  uint16 = 267
	ContentFormatEATUCSJSON  uint16 = 268
)

// numbering maps the claims whose key differs between RFC 9711 and the
// draft-era numbering corecbor <= v0.2 used. Zero means "no such claim".
type numbering struct {
	uptime, submods, swComponents, securityLevel int64
	legacy                                       bool
}

var (
	rfcNumbering    = numbering{uptime: ClaimUptime, submods: ClaimSubmods, swComponents: ClaimPSASoftwareComponents}
	legacyNumbering = numbering{securityLevel: 261, uptime: 266, swComponents: 267, submods: 268, legacy: true}
)

// models reports whether this package decodes claim key k under n.
// Everything else is left to the embedded cwt.ClaimsSet (registered CWT
// claims, then PrivateClaims).
func (n numbering) models(k int64) bool {
	switch k {
	case ClaimNonce, ClaimUEID, ClaimOEMID, ClaimOEMBoot, ClaimDbgStat, ClaimProfile,
		n.uptime, n.submods, n.swComponents:
		return true
	}
	if n.legacy {
		return k == n.securityLevel
	}
	switch k {
	case ClaimSUEIDs, ClaimHWModel, ClaimHWVersion, ClaimLocation, ClaimBootCount,
		ClaimBootSeed, ClaimDLOAs, ClaimSWName, ClaimSWVersion, ClaimManifests,
		ClaimMeasurements, ClaimMeasRes, ClaimIntUse:
		return true
	}
	return false
}
