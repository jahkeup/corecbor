// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

const (
	swCompType      = 1
	swCompMeasValue = 2
	swCompVersion   = 4
	swCompSignerID  = 5
	swCompMeasDesc  = 6

	// decodeBudget bounds decode memory, as cwt does for claims sets.
	decodeBudget = 8 << 20
)

// SecurityLevel is the draft-era EAT security-level claim. RFC 9711
// dropped it (its closest successors are RFC 9783's
// psa-security-lifecycle and EAT's dloas); Claims.SecurityLevel is
// decoded and encoded only under WithLegacyDraftClaimKeys.
type SecurityLevel int64

const (
	SecLevelUnrestricted     SecurityLevel = 1
	SecLevelRestrictedOS     SecurityLevel = 2
	SecLevelSecureRestricted SecurityLevel = 3
	SecLevelHardware         SecurityLevel = 4
)

// DebugStatus represents the EAT debug status claim (RFC 9711 §4.2.9).
type DebugStatus int64

const (
	DebugEnabled          DebugStatus = 0
	DebugDisabled         DebugStatus = 1
	DebugDisabledSince    DebugStatus = 2
	DebugPermanentDisable DebugStatus = 3
)

// SWComponent is one software component measurement in the shape of
// RFC 9783's psa-software-components entry (claim 2399, which
// Claims.SWComponents maps to). eat/psa.SoftwareComponent is an alias.
type SWComponent struct {
	Type                   string
	MeasurementValue       []byte
	Version                string
	SignerID               []byte
	MeasurementDescription string
}

// Submod holds one submodule (RFC 9711 §4.2.18). Exactly one field is
// set: Token (a CBOR nested token: the bytes of a tagged CBOR token,
// e.g. COSE_Sign1), Claims (an inline Claims-Set), JSON (a nested JSON
// token, kept opaque) or Detached (a detached-submodule digest).
type Submod struct {
	// Token is a nested CBOR token (signed CBOR bytes).
	Token []byte
	// Claims is an inline submodule claims set.
	Claims *Claims
	// JSON is a nested JSON token (JSON-Selector text), not decoded here.
	JSON []byte
	// Detached is a detached submodule digest.
	Detached *DetachedDigest
}

// Claims represents an EAT claims set, extending CWT with attestation
// claims. Claims this package does not model (including PSA claims
// other than 2399, cmw and vendor claims) are kept in the embedded
// cwt.ClaimsSet's PrivateClaims and written back by Encode.
type Claims struct {
	cwt.ClaimsSet

	Nonce [][]byte
	UEID  []byte
	OEMId []byte
	// SecurityLevel is the draft-era security-level claim.
	//
	// Deprecated: not an RFC 9711 claim; decoded and encoded only under
	// WithLegacyDraftClaimKeys.
	SecurityLevel SecurityLevel
	SecureBoot    *bool // 262 oemboot
	// Debug is the dbgstat claim. DebugEnabled (0) is not encoded, so it
	// is indistinguishable from absent; set DbgStat to encode an
	// explicit 0.
	Debug        DebugStatus
	Uptime       *uint64
	Profile      string // eat_profile, URI form
	SWComponents []SWComponent
	// Submods holds submodule attestation evidence. Keys are submodule
	// names. Decoding does not verify nested tokens; they are verified
	// only by an Appraiser with a SubmodPolicy (see Appraiser.Appraise).
	Submods map[string]Submod

	// DbgStat is dbgstat with explicit presence. On decode it is set
	// whenever the claim is present (and Debug holds the same value); on
	// encode it takes precedence over Debug.
	DbgStat *DebugStatus
	// ProfileOID is eat_profile in OID form: the BER content octets of
	// the OID, untagged (RFC 9711 §4.3.2).
	ProfileOID []byte
	// OEMIDPEN is oemid in IANA Private Enterprise Number form
	// (RFC 9711 §4.2.3.3); OEMId holds the byte-string forms.
	OEMIDPEN     *int64
	SUEIDs       map[string][]byte // 257
	HWModel      []byte            // 259
	HWVersion    *Version          // 260
	Location     *Location         // 264
	BootCount    *uint64           // 267
	BootSeed     []byte            // 268
	DLOAs        []DLOA            // 269
	SWName       string            // 270
	SWVersion    *Version          // 271
	Manifests    []TypedBytes      // 272
	Measurements []TypedBytes      // 273
	MeasRes      []MeasResGroup    // 274
	IntUse       *IntendedUse      // 275
}

// Encode serializes the Claims as a CBOR map with integer keys, in
// Core Deterministic encoding. NumericDates are whole seconds, as in
// v0.2.2.
func (c *Claims) Encode(opts ...Option) ([]byte, error) {
	cfg := newConfig(opts)
	v, err := c.toValue(cfg)
	if err != nil {
		return nil, err
	}
	b, err := encoder.Encode(nil, v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	return b, nil
}

var encoder = corecbor.NewShared(corecbor.ModeCoreDeterministic)

// toValue builds the claims map: EAT claims from the typed fields, then
// the registered CWT claims and private claims through cwt.
func (c *Claims) toValue(cfg config) (corecbor.Value, error) {
	eat, err := c.eatEntries(cfg)
	if err != nil {
		return corecbor.Value{}, err
	}

	cs := c.ClaimsSet
	cs.Expiration = wholeSeconds(cs.Expiration)
	cs.NotBefore = wholeSeconds(cs.NotBefore)
	cs.IssuedAt = wholeSeconds(cs.IssuedAt)
	priv := make(map[cwt.ClaimKey]corecbor.Value, len(c.PrivateClaims)+len(eat))
	for k, v := range c.PrivateClaims {
		priv[k] = v
	}
	for k, v := range eat {
		priv[cwt.IntKey(k)] = v // typed fields win over a raw claim
	}
	cs.PrivateClaims = priv

	b, err := cs.Encode()
	if err != nil {
		return corecbor.Value{}, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	v, err := corecbor.NewDecoder(corecbor.WithoutInternalArena()).Decode(b)
	if err != nil {
		return corecbor.Value{}, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	return v, nil
}

func wholeSeconds(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return time.Unix(t.Unix(), 0)
}

func intValue(n int64) corecbor.Value {
	if n >= 0 {
		return corecbor.Uint(uint64(n))
	}
	return corecbor.NegInt(uint64(-1 - n))
}

func (c *Claims) eatEntries(cfg config) (map[int64]corecbor.Value, error) {
	n := cfg.num
	m := map[int64]corecbor.Value{}

	if n.legacy {
		if err := c.rejectRFCOnly(); err != nil {
			return nil, err
		}
	} else if c.SecurityLevel != 0 {
		return nil, fmt.Errorf("%w: SecurityLevel is not an RFC 9711 claim; encode with WithLegacyDraftClaimKeys", ErrClaimNumbering)
	}

	if len(c.Nonce) == 1 {
		m[ClaimNonce] = corecbor.Bytes(c.Nonce[0])
	} else if len(c.Nonce) > 1 {
		arr := make([]corecbor.Value, len(c.Nonce))
		for i, v := range c.Nonce {
			arr[i] = corecbor.Bytes(v)
		}
		m[ClaimNonce] = corecbor.MakeArrayFromSlice(arr)
	}
	if len(c.UEID) > 0 {
		m[ClaimUEID] = corecbor.Bytes(c.UEID)
	}
	switch {
	case len(c.OEMId) > 0 && c.OEMIDPEN != nil:
		return nil, fmt.Errorf("%w: oemid: OEMId and OEMIDPEN are both set", ErrMalformedEAT)
	case len(c.OEMId) > 0:
		m[ClaimOEMID] = corecbor.Bytes(c.OEMId)
	case c.OEMIDPEN != nil:
		m[ClaimOEMID] = intValue(*c.OEMIDPEN)
	}
	if n.legacy && c.SecurityLevel != 0 {
		m[n.securityLevel] = intValue(int64(c.SecurityLevel))
	}
	if c.SecureBoot != nil {
		m[ClaimOEMBoot] = corecbor.Bool(*c.SecureBoot)
	}
	switch {
	case c.DbgStat != nil:
		m[ClaimDbgStat] = intValue(int64(*c.DbgStat))
	case c.Debug != 0:
		m[ClaimDbgStat] = intValue(int64(c.Debug))
	}
	if c.Uptime != nil {
		m[n.uptime] = corecbor.Uint(*c.Uptime)
	}
	switch {
	case c.Profile != "" && c.ProfileOID != nil:
		return nil, fmt.Errorf("%w: Profile and ProfileOID are both set", ErrInvalidProfile)
	case c.Profile != "":
		m[ClaimProfile] = corecbor.Text(c.Profile)
	case c.ProfileOID != nil:
		m[ClaimProfile] = corecbor.Bytes(c.ProfileOID)
	}
	if len(c.SWComponents) > 0 {
		m[n.swComponents] = swComponentsValue(c.SWComponents)
	}
	if len(c.Submods) > 0 {
		v, ok, err := c.submodsValue(cfg)
		if err != nil {
			return nil, err
		}
		if ok {
			m[n.submods] = v
		}
	}

	if n.legacy {
		return m, nil
	}
	if len(c.SUEIDs) > 0 {
		pairs := make([]corecbor.MapEntry, 0, len(c.SUEIDs))
		for name, id := range c.SUEIDs {
			pairs = append(pairs, corecbor.MapEntry{Key: corecbor.Text(name), Value: corecbor.Bytes(id)})
		}
		m[ClaimSUEIDs] = corecbor.MakeMapFromSlice(pairs)
	}
	if len(c.HWModel) > 0 {
		m[ClaimHWModel] = corecbor.Bytes(c.HWModel)
	}
	if c.HWVersion != nil {
		m[ClaimHWVersion] = versionValue(*c.HWVersion)
	}
	if c.Location != nil {
		m[ClaimLocation] = locationValue(*c.Location)
	}
	if c.BootCount != nil {
		m[ClaimBootCount] = corecbor.Uint(*c.BootCount)
	}
	if len(c.BootSeed) > 0 {
		m[ClaimBootSeed] = corecbor.Bytes(c.BootSeed)
	}
	if len(c.DLOAs) > 0 {
		arr := make([]corecbor.Value, len(c.DLOAs))
		for i, d := range c.DLOAs {
			items := []corecbor.Value{corecbor.Text(d.Registrar), corecbor.Text(d.PlatformLabel)}
			if d.ApplicationLabel != "" {
				items = append(items, corecbor.Text(d.ApplicationLabel))
			}
			arr[i] = corecbor.MakeArrayFromSlice(items)
		}
		m[ClaimDLOAs] = corecbor.MakeArrayFromSlice(arr)
	}
	if c.SWName != "" {
		m[ClaimSWName] = corecbor.Text(c.SWName)
	}
	if c.SWVersion != nil {
		m[ClaimSWVersion] = versionValue(*c.SWVersion)
	}
	if len(c.Manifests) > 0 {
		m[ClaimManifests] = typedBytesValue(c.Manifests)
	}
	if len(c.Measurements) > 0 {
		m[ClaimMeasurements] = typedBytesValue(c.Measurements)
	}
	if len(c.MeasRes) > 0 {
		arr := make([]corecbor.Value, len(c.MeasRes))
		for i, g := range c.MeasRes {
			res := make([]corecbor.Value, len(g.Results))
			for j, r := range g.Results {
				id := corecbor.Bytes(r.ID)
				if r.IsText {
					id = corecbor.Text(r.IDText)
				}
				res[j] = corecbor.MakeArray(id, intValue(int64(r.Result)))
			}
			arr[i] = corecbor.MakeArray(corecbor.Text(g.System), corecbor.MakeArrayFromSlice(res))
		}
		m[ClaimMeasRes] = corecbor.MakeArrayFromSlice(arr)
	}
	if c.IntUse != nil {
		m[ClaimIntUse] = intValue(int64(*c.IntUse))
	}
	return m, nil
}

// rejectRFCOnly refuses claims the draft-era numbering cannot carry.
func (c *Claims) rejectRFCOnly() error {
	var name string
	switch {
	case c.ProfileOID != nil:
		name = "ProfileOID"
	case c.OEMIDPEN != nil:
		name = "OEMIDPEN"
	case len(c.SUEIDs) > 0:
		name = "SUEIDs"
	case len(c.HWModel) > 0:
		name = "HWModel"
	case c.HWVersion != nil:
		name = "HWVersion"
	case c.Location != nil:
		name = "Location"
	case c.BootCount != nil:
		name = "BootCount"
	case len(c.BootSeed) > 0:
		name = "BootSeed"
	case len(c.DLOAs) > 0:
		name = "DLOAs"
	case c.SWName != "":
		name = "SWName"
	case c.SWVersion != nil:
		name = "SWVersion"
	case len(c.Manifests) > 0:
		name = "Manifests"
	case len(c.Measurements) > 0:
		name = "Measurements"
	case len(c.MeasRes) > 0:
		name = "MeasRes"
	case c.IntUse != nil:
		name = "IntUse"
	default:
		for sn, s := range c.Submods {
			if s.JSON != nil || s.Detached != nil {
				return fmt.Errorf("%w: submods[%q]: JSON and detached submodules exist only in RFC 9711", ErrClaimNumbering, sn)
			}
		}
		return nil
	}
	return fmt.Errorf("%w: %s exists only in RFC 9711 numbering", ErrClaimNumbering, name)
}

func swComponentsValue(sws []SWComponent) corecbor.Value {
	arr := make([]corecbor.Value, len(sws))
	for i, sw := range sws {
		var cm []corecbor.MapEntry
		if sw.Type != "" {
			cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompType), Value: corecbor.Text(sw.Type)})
		}
		if len(sw.MeasurementValue) > 0 {
			cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompMeasValue), Value: corecbor.Bytes(sw.MeasurementValue)})
		}
		if sw.Version != "" {
			cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompVersion), Value: corecbor.Text(sw.Version)})
		}
		if len(sw.SignerID) > 0 {
			cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompSignerID), Value: corecbor.Bytes(sw.SignerID)})
		}
		if sw.MeasurementDescription != "" {
			cm = append(cm, corecbor.MapEntry{Key: corecbor.Uint(swCompMeasDesc), Value: corecbor.Text(sw.MeasurementDescription)})
		}
		arr[i] = corecbor.MakeMapFromSlice(cm)
	}
	return corecbor.MakeArrayFromSlice(arr)
}

func (c *Claims) submodsValue(cfg config) (corecbor.Value, bool, error) {
	var sm []corecbor.MapEntry
	for name, sub := range c.Submods {
		var val corecbor.Value
		switch {
		case sub.Token != nil:
			val = corecbor.Bytes(sub.Token)
		case sub.Claims != nil:
			v, err := sub.Claims.toValue(cfg)
			if err != nil {
				return corecbor.Value{}, false, fmt.Errorf("submods[%q]: %w", name, err)
			}
			val = v
		case sub.JSON != nil:
			val = corecbor.Text(string(sub.JSON))
		case sub.Detached != nil:
			alg := intValue(int64(sub.Detached.Alg))
			if sub.Detached.AlgName != "" {
				alg = corecbor.Text(sub.Detached.AlgName)
			}
			val = corecbor.MakeArray(alg, corecbor.Bytes(sub.Detached.Digest))
		default:
			continue
		}
		sm = append(sm, corecbor.MapEntry{Key: corecbor.Text(name), Value: val})
	}
	if len(sm) == 0 {
		return corecbor.Value{}, false, nil
	}
	return corecbor.MakeMapFromSlice(sm), true, nil
}

func versionValue(v Version) corecbor.Value {
	items := []corecbor.Value{corecbor.Text(v.Version)}
	if v.Scheme != nil {
		items = append(items, intValue(*v.Scheme))
	}
	return corecbor.MakeArrayFromSlice(items)
}

func typedBytesValue(ts []TypedBytes) corecbor.Value {
	arr := make([]corecbor.Value, len(ts))
	for i, t := range ts {
		var ct corecbor.Value
		if t.ContentFormat != nil {
			ct = corecbor.Uint(*t.ContentFormat)
		} else {
			ct = corecbor.Text(t.MediaType)
		}
		arr[i] = corecbor.MakeArray(ct, corecbor.Bytes(t.Value))
	}
	return corecbor.MakeArrayFromSlice(arr)
}

func numberValue(f float64) corecbor.Value {
	if f == math.Trunc(f) && f >= math.MinInt64 && f < math.MaxInt64 {
		return intValue(int64(f))
	}
	return corecbor.Float64(f)
}

func locationValue(l Location) corecbor.Value {
	m := []corecbor.MapEntry{
		{Key: corecbor.Uint(1), Value: numberValue(l.Latitude)},
		{Key: corecbor.Uint(2), Value: numberValue(l.Longitude)},
	}
	opt := func(k uint64, p *float64) {
		if p != nil {
			m = append(m, corecbor.MapEntry{Key: corecbor.Uint(k), Value: numberValue(*p)})
		}
	}
	opt(3, l.Altitude)
	opt(4, l.Accuracy)
	opt(5, l.AltitudeAccuracy)
	switch {
	case l.Heading != nil:
		opt(6, l.Heading)
	case l.HeadingNull:
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(6), Value: corecbor.Null()})
	}
	opt(7, l.Speed)
	if l.Timestamp != nil {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(8), Value: intValue(*l.Timestamp)})
	}
	if l.Age != nil {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(9), Value: corecbor.Uint(*l.Age)})
	}
	return corecbor.MakeMapFromSlice(m)
}

// DecodeClaims deserializes a CBOR-encoded claims map into EAT Claims.
//
// It keeps v0.2.2's value acceptance (no nonce-length, UEID or dbgstat
// range checks; use Claims.Validate for RFC 9711's constraints),
// rejects duplicate claims (RFC 8392 §7.2) and bounds decode memory.
// Claims it does not model are kept in PrivateClaims. Errors wrap
// ErrMalformedEAT; errors about one claim are *cwt.ClaimError.
func DecodeClaims(data []byte, opts ...Option) (*Claims, error) {
	cfg := newConfig(opts)
	v, err := corecbor.NewDecoder(
		corecbor.WithoutInternalArena(),
		corecbor.RejectDuplicateMapKeys(),
		corecbor.WithMemoryBudget(decodeBudget),
	).Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	return decodeClaimsValue(v, cfg, 0)
}

// maxSubmodDepth bounds inline-submodule recursion.
const maxSubmodDepth = 16

func decodeClaimsValue(v corecbor.Value, cfg config, depth int) (*Claims, error) {
	if v.Kind != corecbor.KindMap {
		return nil, fmt.Errorf("%w: expected map, got kind %d", ErrMalformedEAT, v.Kind)
	}
	if depth > maxSubmodDepth {
		return nil, fmt.Errorf("%w: submodules nested deeper than %d", ErrMalformedEAT, maxSubmodDepth)
	}

	c := &Claims{}
	var rest []corecbor.MapEntry
	for _, entry := range v.Map() {
		// Checked here because rest is re-encoded deterministically
		// before cwt sees it, which turns these keys into integers.
		if integerBignumKey(entry.Key) {
			return nil, fmt.Errorf("%w: claim key is a bignum with an integer value", ErrMalformedEAT)
		}
		k, ok := intKey(entry.Key)
		if !ok || !cfg.num.models(k) {
			rest = append(rest, entry)
			continue
		}
		if err := c.decodeClaim(k, entry.Value, cfg, depth); err != nil {
			return nil, &cwt.ClaimError{Key: cwt.IntKey(k), Err: err}
		}
	}

	if len(rest) > 0 {
		b, err := restEncoder.Encode(nil, corecbor.MakeMapFromSlice(rest))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
		}
		cs, err := cwt.DecodeClaimsSet(b)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
		}
		c.ClaimsSet = *cs
	}
	return c, nil
}

// restEncoder re-encodes the claims handed to cwt. It is lossless for
// anything the forgiving decoder accepted.
var restEncoder = corecbor.NewShared(corecbor.ModeCoreDeterministic,
	corecbor.AllowInvalidUTF8(), corecbor.AllowNonFiniteFloats())

// integerBignumKey reports whether k is a tag 2/3 bignum whose value
// fits a CBOR integer; see cwt's check of the same name.
func integerBignumKey(k corecbor.Value) bool {
	if k.Kind != corecbor.KindTag ||
		(k.TagID() != corecbor.TagUnsignedBignum && k.TagID() != corecbor.TagNegativeBignum) {
		return false
	}
	in := k.TagInner()
	return in.Kind == corecbor.KindBytes && len(bytes.TrimLeft(in.BytesVal(), "\x00")) <= 8
}

// intKey returns k as an int64 when it is an integer in the int64
// range; anything else (other kinds, or integers beyond int64) is
// reported as not an integer key rather than wrapping.
func intKey(k corecbor.Value) (int64, bool) {
	n, err := k.Int64()
	return n, err == nil
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformedEAT}, args...)...)
}

func (c *Claims) decodeClaim(k int64, val corecbor.Value, cfg config, depth int) error {
	n := cfg.num
	switch k {
	case ClaimNonce:
		nonces, err := parseNonce(val)
		if err != nil {
			return err
		}
		c.Nonce = nonces
	case ClaimUEID:
		if val.Kind != corecbor.KindBytes {
			return malformed("UEID must be bytes")
		}
		c.UEID = val.BytesVal()
	case ClaimOEMID:
		switch val.Kind {
		case corecbor.KindBytes:
			c.OEMId = val.BytesVal()
		case corecbor.KindUint, corecbor.KindNegInt:
			pen, ok := intKey(val)
			if !ok {
				return malformed("oemid PEN out of range")
			}
			c.OEMIDPEN = &pen
		default:
			return malformed("OEMId must be bytes or an integer")
		}
	case ClaimOEMBoot:
		if val.Kind != corecbor.KindBool {
			return malformed("secure-boot must be bool")
		}
		b := val.BoolVal()
		c.SecureBoot = &b
	case ClaimDbgStat:
		d, err := parseIntClaim(val)
		if err != nil {
			return malformed("debug: %w", err)
		}
		c.Debug = DebugStatus(d)
		ds := DebugStatus(d)
		c.DbgStat = &ds
	case ClaimProfile:
		switch val.Kind {
		case corecbor.KindText:
			c.Profile = val.TextVal()
		case corecbor.KindBytes:
			if n.legacy {
				return malformed("profile must be text")
			}
			c.ProfileOID = val.BytesVal()
		default:
			return malformed("profile must be text or an OID")
		}
	case n.uptime:
		u, err := parseUintClaim(val)
		if err != nil {
			return malformed("uptime: %w", err)
		}
		c.Uptime = &u
	case n.swComponents:
		sws, err := parseSWComponents(val)
		if err != nil {
			return err
		}
		c.SWComponents = sws
	case n.submods:
		return c.decodeSubmods(val, cfg, depth)
	}
	if n.legacy {
		if k == n.securityLevel {
			lvl, err := parseIntClaim(val)
			if err != nil {
				return malformed("security-level: %w", err)
			}
			c.SecurityLevel = SecurityLevel(lvl)
		}
		return nil
	}
	return c.decodeRFCClaim(k, val)
}

func (c *Claims) decodeRFCClaim(k int64, val corecbor.Value) error {
	var err error
	switch k {
	case ClaimSUEIDs:
		if val.Kind != corecbor.KindMap {
			return malformed("sueids must be a map")
		}
		c.SUEIDs = make(map[string][]byte, len(val.Map()))
		for _, e := range val.Map() {
			if e.Key.Kind != corecbor.KindText || e.Value.Kind != corecbor.KindBytes {
				return malformed("sueids entries must be text => bytes")
			}
			c.SUEIDs[e.Key.TextVal()] = e.Value.BytesVal()
		}
	case ClaimHWModel:
		if val.Kind != corecbor.KindBytes {
			return malformed("hwmodel must be bytes")
		}
		c.HWModel = val.BytesVal()
	case ClaimHWVersion:
		c.HWVersion, err = parseVersion(val, "hwversion")
	case ClaimLocation:
		c.Location, err = parseLocation(val)
	case ClaimBootCount:
		var u uint64
		u, err = parseUintClaim(val)
		if err == nil {
			c.BootCount = &u
		}
	case ClaimBootSeed:
		if val.Kind != corecbor.KindBytes {
			return malformed("bootseed must be bytes")
		}
		c.BootSeed = val.BytesVal()
	case ClaimDLOAs:
		c.DLOAs, err = parseDLOAs(val)
	case ClaimSWName:
		if val.Kind != corecbor.KindText {
			return malformed("swname must be text")
		}
		c.SWName = val.TextVal()
	case ClaimSWVersion:
		c.SWVersion, err = parseVersion(val, "swversion")
	case ClaimManifests:
		c.Manifests, err = parseTypedBytes(val, "manifests")
	case ClaimMeasurements:
		c.Measurements, err = parseTypedBytes(val, "measurements")
	case ClaimMeasRes:
		c.MeasRes, err = parseMeasRes(val)
	case ClaimIntUse:
		var n int64
		n, err = parseIntClaim(val)
		if err == nil {
			iu := IntendedUse(n)
			c.IntUse = &iu
		}
	}
	if err != nil && !isMalformed(err) {
		err = malformed("%w", err)
	}
	return err
}

func isMalformed(err error) bool { return errors.Is(err, ErrMalformedEAT) }

func (c *Claims) decodeSubmods(val corecbor.Value, cfg config, depth int) error {
	if val.Kind != corecbor.KindMap {
		return malformed("submods must be map")
	}
	c.Submods = make(map[string]Submod, len(val.Map()))
	for _, e := range val.Map() {
		if e.Key.Kind != corecbor.KindText {
			return malformed("submod key must be text")
		}
		name := e.Key.TextVal()
		switch e.Value.Kind {
		case corecbor.KindBytes:
			c.Submods[name] = Submod{Token: e.Value.BytesVal()}
		case corecbor.KindMap:
			inline, err := decodeClaimsValue(e.Value, cfg, depth+1)
			if err != nil {
				return fmt.Errorf("%w: submods[%q]: %w", ErrMalformedEAT, name, err)
			}
			c.Submods[name] = Submod{Claims: inline}
		case corecbor.KindText:
			if cfg.num.legacy {
				return malformed("submod[%q] value must be bytes or map", name)
			}
			c.Submods[name] = Submod{JSON: []byte(e.Value.TextVal())}
		case corecbor.KindArray:
			if cfg.num.legacy {
				return malformed("submod[%q] value must be bytes or map", name)
			}
			d, err := parseDetachedDigest(e.Value)
			if err != nil {
				return fmt.Errorf("submods[%q]: %w", name, err)
			}
			c.Submods[name] = Submod{Detached: d}
		default:
			return malformed("submod[%q] value must be a map, bytes, text or a detached digest", name)
		}
	}
	return nil
}

func parseDetachedDigest(v corecbor.Value) (*DetachedDigest, error) {
	items := v.Array()
	if len(items) != 2 || items[1].Kind != corecbor.KindBytes {
		return nil, malformed("detached submodule digest must be [alg, digest]")
	}
	d := &DetachedDigest{Digest: items[1].BytesVal()}
	switch items[0].Kind {
	case corecbor.KindText:
		d.AlgName = items[0].TextVal()
	case corecbor.KindUint, corecbor.KindNegInt:
		a, ok := intKey(items[0])
		if !ok {
			return nil, malformed("detached digest algorithm out of range")
		}
		d.Alg = cose.Algorithm(a)
	default:
		return nil, malformed("detached digest algorithm must be text or an integer")
	}
	return d, nil
}

func parseSWComponents(val corecbor.Value) ([]SWComponent, error) {
	if val.Kind != corecbor.KindArray {
		return nil, malformed("sw-components must be array")
	}
	arr := val.Array()
	swcs := make([]SWComponent, len(arr))
	for i, elem := range arr {
		if elem.Kind != corecbor.KindMap {
			return nil, malformed("sw-component[%d] must be map", i)
		}
		var sw SWComponent
		for _, e := range elem.Map() {
			k, ok := intKey(e.Key)
			if !ok {
				continue
			}
			switch k {
			case swCompType:
				if e.Value.Kind == corecbor.KindText {
					sw.Type = e.Value.TextVal()
				}
			case swCompMeasValue:
				if e.Value.Kind == corecbor.KindBytes {
					sw.MeasurementValue = e.Value.BytesVal()
				}
			case swCompVersion:
				if e.Value.Kind == corecbor.KindText {
					sw.Version = e.Value.TextVal()
				}
			case swCompSignerID:
				if e.Value.Kind == corecbor.KindBytes {
					sw.SignerID = e.Value.BytesVal()
				}
			case swCompMeasDesc:
				if e.Value.Kind == corecbor.KindText {
					sw.MeasurementDescription = e.Value.TextVal()
				}
			}
		}
		swcs[i] = sw
	}
	return swcs, nil
}

func parseVersion(v corecbor.Value, what string) (*Version, error) {
	items := v.Array()
	if v.Kind != corecbor.KindArray || len(items) < 1 || len(items) > 2 || items[0].Kind != corecbor.KindText {
		return nil, malformed("%s must be [version, ?scheme]", what)
	}
	out := &Version{Version: items[0].TextVal()}
	if len(items) == 2 {
		s, err := parseIntClaim(items[1])
		if err != nil {
			return nil, malformed("%s scheme: %w", what, err)
		}
		out.Scheme = &s
	}
	return out, nil
}

func parseNumber(v corecbor.Value) (float64, error) {
	switch v.Kind {
	case corecbor.KindUint:
		return float64(v.UintVal()), nil
	case corecbor.KindNegInt:
		return -1 - float64(v.NegIntVal()), nil
	case corecbor.KindFloat32:
		return float64(v.Float32Val()), nil
	case corecbor.KindFloat64:
		return v.Float64Val(), nil
	default:
		return 0, fmt.Errorf("expected number, got kind %d", v.Kind)
	}
}

func parseLocation(v corecbor.Value) (*Location, error) {
	if v.Kind != corecbor.KindMap {
		return nil, malformed("location must be a map")
	}
	l := &Location{}
	var haveLat, haveLong bool
	num := func(e corecbor.MapEntry, what string) (*float64, error) {
		f, err := parseNumber(e.Value)
		if err != nil {
			return nil, malformed("location %s: %w", what, err)
		}
		return &f, nil
	}
	for _, e := range v.Map() {
		k, ok := intKey(e.Key)
		if !ok {
			continue
		}
		var err error
		switch k {
		case 1:
			var f *float64
			if f, err = num(e, "latitude"); err == nil {
				l.Latitude, haveLat = *f, true
			}
		case 2:
			var f *float64
			if f, err = num(e, "longitude"); err == nil {
				l.Longitude, haveLong = *f, true
			}
		case 3:
			l.Altitude, err = num(e, "altitude")
		case 4:
			l.Accuracy, err = num(e, "accuracy")
		case 5:
			l.AltitudeAccuracy, err = num(e, "altitude-accuracy")
		case 6:
			if e.Value.Kind == corecbor.KindNull {
				l.HeadingNull = true // erratum 8776
			} else {
				l.Heading, err = num(e, "heading")
			}
		case 7:
			l.Speed, err = num(e, "speed")
		case 8:
			var t int64
			t, err = parseIntClaim(e.Value)
			if err == nil {
				l.Timestamp = &t
			}
		case 9:
			var a uint64
			a, err = parseUintClaim(e.Value)
			if err == nil {
				l.Age = &a
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if !haveLat || !haveLong {
		return nil, malformed("location requires latitude and longitude")
	}
	return l, nil
}

func parseDLOAs(v corecbor.Value) ([]DLOA, error) {
	if v.Kind != corecbor.KindArray || len(v.Array()) == 0 {
		return nil, malformed("dloas must be a non-empty array")
	}
	out := make([]DLOA, len(v.Array()))
	for i, d := range v.Array() {
		items := d.Array()
		if d.Kind != corecbor.KindArray || len(items) < 2 || len(items) > 3 {
			return nil, malformed("dloa[%d] must be [registrar, platform, ?application]", i)
		}
		for _, it := range items {
			if it.Kind != corecbor.KindText {
				return nil, malformed("dloa[%d] members must be text", i)
			}
		}
		out[i] = DLOA{Registrar: items[0].TextVal(), PlatformLabel: items[1].TextVal()}
		if len(items) == 3 {
			out[i].ApplicationLabel = items[2].TextVal()
		}
	}
	return out, nil
}

func parseTypedBytes(v corecbor.Value, what string) ([]TypedBytes, error) {
	if v.Kind != corecbor.KindArray || len(v.Array()) == 0 {
		return nil, malformed("%s must be a non-empty array", what)
	}
	out := make([]TypedBytes, len(v.Array()))
	for i, f := range v.Array() {
		items := f.Array()
		if f.Kind != corecbor.KindArray || len(items) != 2 || items[1].Kind != corecbor.KindBytes {
			return nil, malformed("%s[%d] must be [content-type, bytes]", what, i)
		}
		switch items[0].Kind {
		case corecbor.KindUint:
			cf := items[0].UintVal()
			out[i].ContentFormat = &cf
		case corecbor.KindText:
			out[i].MediaType = items[0].TextVal()
		default:
			return nil, malformed("%s[%d] content-type must be a content-format number or media type", what, i)
		}
		out[i].Value = items[1].BytesVal()
	}
	return out, nil
}

func parseMeasRes(v corecbor.Value) ([]MeasResGroup, error) {
	if v.Kind != corecbor.KindArray || len(v.Array()) == 0 {
		return nil, malformed("measres must be a non-empty array")
	}
	out := make([]MeasResGroup, len(v.Array()))
	for i, g := range v.Array() {
		items := g.Array()
		if g.Kind != corecbor.KindArray || len(items) != 2 || items[0].Kind != corecbor.KindText || items[1].Kind != corecbor.KindArray {
			return nil, malformed("measres[%d] must be [system, [+ result]]", i)
		}
		out[i].System = items[0].TextVal()
		for j, r := range items[1].Array() {
			ri := r.Array()
			if r.Kind != corecbor.KindArray || len(ri) != 2 {
				return nil, malformed("measres[%d][%d] must be [id, result]", i, j)
			}
			var ind MeasResIndividual
			switch ri[0].Kind {
			case corecbor.KindText:
				ind.IDText, ind.IsText = ri[0].TextVal(), true
			case corecbor.KindBytes:
				ind.ID = ri[0].BytesVal()
			default:
				return nil, malformed("measres[%d][%d] id must be text or bytes", i, j)
			}
			res, err := parseIntClaim(ri[1])
			if err != nil {
				return nil, malformed("measres[%d][%d] result: %w", i, j, err)
			}
			ind.Result = MeasResult(res)
			out[i].Results = append(out[i].Results, ind)
		}
	}
	return out, nil
}

func parseNonce(v corecbor.Value) ([][]byte, error) {
	switch v.Kind {
	case corecbor.KindBytes:
		return [][]byte{v.BytesVal()}, nil
	case corecbor.KindArray:
		items := v.Array()
		nonces := make([][]byte, len(items))
		for i, elem := range items {
			if elem.Kind != corecbor.KindBytes {
				return nil, malformed("nonce array element %d must be bytes", i)
			}
			nonces[i] = elem.BytesVal()
		}
		return nonces, nil
	default:
		return nil, malformed("nonce must be bytes or array, got kind %d", v.Kind)
	}
}

func parseIntClaim(v corecbor.Value) (int64, error) {
	if v.Kind != corecbor.KindUint && v.Kind != corecbor.KindNegInt {
		return 0, fmt.Errorf("%w: expected integer, got kind %d", ErrMalformedEAT, v.Kind)
	}
	n, ok := intKey(v)
	if !ok {
		return 0, fmt.Errorf("%w: integer out of range", ErrMalformedEAT)
	}
	return n, nil
}

func parseUintClaim(v corecbor.Value) (uint64, error) {
	n, err := v.Uint64()
	if err != nil {
		return 0, fmt.Errorf("%w: expected unsigned integer, got kind %d", ErrMalformedEAT, v.Kind)
	}
	return n, nil
}

// sortedSubmodNames returns the submodule names in sorted order, so
// appraisal reports failures deterministically.
func sortedSubmodNames(m map[string]Submod) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
