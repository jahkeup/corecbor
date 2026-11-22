// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"fmt"

	"github.com/jahkeup/corecbor/cose"
)

// DebugDisabledFullyAndPermanently is RFC 9711 §4.2.9.5's dbgstat 4,
// which v0.2.2 did not define.
const DebugDisabledFullyAndPermanently DebugStatus = 4

// UEID is a Universal Entity ID (RFC 9711 §4.2.1). Claims.UEID keeps
// its []byte type; convert with UEID(c.UEID).
type UEID []byte

// UEIDType is a UEID's first byte (RFC 9711 §4.2.1.1, Table 1).
type UEIDType uint8

const (
	UEIDTypeRAND UEIDType = 0x01
	UEIDTypeEUI  UEIDType = 0x02
	UEIDTypeIMEI UEIDType = 0x03
)

// Type returns the UEID's type byte, or 0 for an empty UEID.
func (u UEID) Type() UEIDType {
	if len(u) == 0 {
		return 0
	}
	return UEIDType(u[0])
}

// Validate checks RFC 9711 §4.2.1: total length 7..33, a known type
// byte, and that type's length rules (RAND: 128, 192 or 256 bits; EUI:
// EUI-48, EUI-60 or EUI-64; IMEI: 14 digit bytes, each 0..9).
func (u UEID) Validate() error {
	if len(u) < 7 || len(u) > 33 {
		return fmt.Errorf("%w: length %d outside 7..33", ErrInvalidUEID, len(u))
	}
	body := len(u) - 1
	switch u.Type() {
	case UEIDTypeRAND:
		if body != 16 && body != 24 && body != 32 {
			return fmt.Errorf("%w: RAND UEID must carry 128, 192 or 256 bits, got %d bytes", ErrInvalidUEID, body)
		}
	case UEIDTypeEUI:
		if body < 6 || body > 8 {
			return fmt.Errorf("%w: EUI UEID must carry an EUI-48, EUI-60 or EUI-64, got %d bytes", ErrInvalidUEID, body)
		}
	case UEIDTypeIMEI:
		if body != 14 {
			return fmt.Errorf("%w: IMEI UEID must carry 14 digits, got %d bytes", ErrInvalidUEID, body)
		}
		for _, d := range u[1:] {
			if d > 9 {
				return fmt.Errorf("%w: IMEI digit byte 0x%02x is not 0..9", ErrInvalidUEID, d)
			}
		}
	default:
		return fmt.Errorf("%w: unknown type byte 0x%02x", ErrInvalidUEID, byte(u.Type()))
	}
	return nil
}

// Version is the hwversion / swversion claim value (RFC 9711 §4.2.5,
// §4.2.7): a version string and an optional CoSWID version scheme.
type Version struct {
	Version string
	Scheme  *int64
}

// Location is the location claim (RFC 9711 §4.2.10). Latitude and
// longitude are required; the rest are optional. Heading may be
// present but null for a stationary entity (erratum 8776); that is
// represented as HeadingNull with Heading nil.
type Location struct {
	Latitude         float64
	Longitude        float64
	Altitude         *float64
	Accuracy         *float64
	AltitudeAccuracy *float64
	Heading          *float64
	HeadingNull      bool
	Speed            *float64
	Timestamp        *int64 // ~time-int: epoch seconds
	Age              *uint64
}

// DLOA is one Digital Letter of Approval reference (RFC 9711 §4.2.14).
type DLOA struct {
	Registrar        string // general-uri
	PlatformLabel    string
	ApplicationLabel string // optional
}

// TypedBytes is a [content-type, content] pair used by the manifests
// and measurements claims (RFC 9711 §4.2.15, §4.2.16). CBOR tokens
// carry a CoAP content-format number; MediaType is kept for producers
// that use a media-type string instead.
type TypedBytes struct {
	ContentFormat *uint64
	MediaType     string
	Value         []byte
}

// MeasResult is an individual-result's outcome (RFC 9711 §4.2.17).
type MeasResult int64

const (
	MeasResultSuccess MeasResult = 1
	MeasResultFail    MeasResult = 2
	MeasResultNotRun  MeasResult = 3
	MeasResultAbsent  MeasResult = 4
)

// MeasResIndividual is one [result-id, result] entry. The result ID is
// text (IDText, IsText true) or bytes (ID).
type MeasResIndividual struct {
	ID     []byte
	IDText string
	IsText bool
	Result MeasResult
}

// MeasResGroup is one measurement-results-group (RFC 9711 §4.2.17).
type MeasResGroup struct {
	System  string
	Results []MeasResIndividual
}

// IntendedUse is the intuse claim (RFC 9711 §4.3.3, §10.5 registry).
type IntendedUse int64

const (
	IntendedUseGeneric           IntendedUse = 1
	IntendedUseRegistration      IntendedUse = 2
	IntendedUseProvisioning      IntendedUse = 3
	IntendedUseCertificateIssue  IntendedUse = 4
	IntendedUseProofOfPossession IntendedUse = 5
)

// DetachedDigest is a Detached-Submodule-Digest (RFC 9711 §4.2.18.2):
// a COSE hash algorithm identifier (integer or text form) and the
// digest of the detached Claims-Set's encoding.
type DetachedDigest struct {
	Alg     cose.Algorithm // integer form; 0 when AlgName is set
	AlgName string         // text form, when the token uses it
	Digest  []byte
}
