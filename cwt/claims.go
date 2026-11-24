// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/internal/asreceived"
	"github.com/jahkeup/corecbor/internal/rawvalue"
)

// cnf map keys per RFC 8747.
const (
	cnfKeyByCOSEKey = 1
	cnfKeyEncrypted = 2
	cnfKeyByKid     = 3
)

// decodeBudget bounds the memory a single claims decode may allocate.
const decodeBudget = 8 << 20

// Confirmation represents the cnf (confirmation) claim (key 8)
// per RFC 8747. Binds the token to a specific cryptographic key. A
// decoded Confirmation holds at most one of Key and Encrypted/
// EncryptedKey (RFC 8747 §3.1), either possibly with a KeyID naming the
// same key.
type Confirmation struct {
	Key   *cose.Key // cnf map key 1: COSE_Key by value
	KeyID []byte    // cnf map key 3: key ID reference

	// Encrypted is cnf map key 2. On decode it holds the encoded bytes
	// of the member: the byte string v0.2.2 emitted, or the encoded
	// COSE_Encrypt0/COSE_Encrypt array RFC 8747 §3.3 specifies. On
	// encode it is emitted as a byte string, as in v0.2.2.
	//
	// Deprecated: use EncryptedKey, which encodes per RFC 8747 §3.3.
	Encrypted []byte

	// EncryptedKey is cnf map key 2 as RFC 8747 §3.3 defines it: a
	// COSE_Encrypt0 or COSE_Encrypt carrying a COSE_Key. It takes
	// precedence over Encrypted on encode.
	EncryptedKey *EncryptedKey
}

// EncryptedKey is the Encrypted_COSE_Key of RFC 8747 §3.3. Exactly one
// field is set.
type EncryptedKey struct {
	Encrypt0 *cose.Encrypt0
	Encrypt  *cose.Encrypt
}

// members reports which understood proof-of-possession members c
// carries: a COSE_Key (1), an Encrypted_COSE_Key (2), a kid (3). An
// empty Encrypted or KeyID carries nothing.
func (c *Confirmation) members() (key, enc, kid bool) {
	return c.Key != nil, c.EncryptedKey != nil || len(c.Encrypted) > 0, len(c.KeyID) > 0
}

// errTwoKeys is RFC 8747 §3.1: "At most one of the COSE_Key and
// Encrypted_COSE_Key confirmation values ... may be present". A kid
// may accompany either, identifying the same key.
const errTwoKeys = "COSE_Key and Encrypted_COSE_Key both present (RFC 8747 §3.1)"

// checkMethod is Validator.RequireConfirmation: c must identify exactly
// one proof-of-possession key with members this package understands
// (RFC 8747 §3.1): a COSE_Key or an Encrypted_COSE_Key, either with an
// optional kid, or a kid alone. A cnf that is empty or holds only
// members this package doesn't understand (which decoding ignores)
// carries none.
func (c *Confirmation) checkMethod() error {
	if c == nil {
		return &ClaimError{Key: IntKey(ClaimCnf), Err: ErrMissingConfirmation}
	}
	key, enc, kid := c.members()
	switch {
	case key && enc:
		return claimErr(IntKey(ClaimCnf), errTwoKeys, nil)
	case !key && !enc && !kid:
		return &ClaimError{Key: IntKey(ClaimCnf), Err: fmt.Errorf("%w: cnf carries no understood proof-of-possession method", ErrMissingConfirmation)}
	}
	return nil
}

// checkNotExposed returns ErrSymmetricKeyNotEncrypted, in a *ClaimError
// for cnf, when c carries a symmetric COSE_Key by value: RFC 8747 §3.2
// permits that only in an encrypted CWT. Callers that put claims in
// plaintext (signed or MACed CWTs, COSE headers) call it.
func (c *ClaimsSet) checkNotExposed() error {
	if c == nil || c.Confirmation == nil || c.Confirmation.Key == nil {
		return nil
	}
	if c.Confirmation.Key.KeyType() == cose.KeyTypeSymmetric {
		return &ClaimError{Key: IntKey(ClaimCnf), Err: fmt.Errorf(
			"%w: carry it as an Encrypted_COSE_Key (Confirmation.EncryptedKey) or encrypt the CWT (Seal)",
			ErrSymmetricKeyNotEncrypted,
		)}
	}
	return nil
}

// Match reports whether k is the key bound by c. When c carries the key
// by value, the key decides: k must have the same RFC 9679 thumbprint
// (public parameters only), and, if both c and k carry a key ID, the
// same one. Otherwise k must have c's key ID.
func (c *Confirmation) Match(k *cose.Key) bool {
	if c == nil || k == nil {
		return false
	}
	if c.Key == nil {
		return len(c.KeyID) > 0 && bytes.Equal(c.KeyID, k.ID())
	}
	if len(c.KeyID) > 0 && len(k.ID()) > 0 && !bytes.Equal(c.KeyID, k.ID()) {
		return false
	}
	a, err := c.Key.Thumbprint(crypto.SHA256)
	if err != nil {
		return false
	}
	b, err := k.Thumbprint(crypto.SHA256)
	return err == nil && bytes.Equal(a, b)
}

// Scope is the ACE "scope" claim: text (space-separated scope tokens)
// or bytes (RFC 9200 §5.8.1).
type Scope struct {
	Text   string
	Bytes  []byte
	IsText bool
}

// ClaimsSet represents the set of claims in a CWT.
type ClaimsSet struct {
	Issuer       string
	Subject      string
	Audience     string // the single-string aud form
	Expiration   time.Time
	NotBefore    time.Time
	IssuedAt     time.Time
	CWTID        []byte
	Confirmation *Confirmation

	// Private holds claims this package does not model, keyed by int64
	// or string. Claims labeled by an integer outside the int64 range
	// are not representable as a Go map key here; they appear only in
	// PrivateClaims. Other labels (byte strings, arrays, ...) are not
	// claim keys at all and are rejected (RFC 8392 §3). The ACE
	// claims 9, 38, 39 and 40 also stay in Private, as in v0.2.2, besides
	// populating their typed fields.
	//
	// Deprecated: use PrivateClaims, which represents every claim label
	// exactly. Private keeps working for the life of the v0.x line.
	Private map[any]any

	// Audiences is the aud claim in either form (RFC 9200 §5.10.1: a
	// StringOrURI or an array of them). A single-string aud is also in
	// Audience. Encoding uses Audiences when it has more than one
	// element, and otherwise Audience (or the single element).
	Audiences []string

	// The RFC 9200 claims; nil when absent. Decoding an ill-typed one
	// is an error naming it.
	Scope      *Scope  // claim 9: text or bytes
	ACEProfile *int64  // claim 38: an integer
	CNonce     []byte  // claim 39: bytes
	Exi        *uint64 // claim 40: seconds from first receipt; see Validator.ExiFirstSeen

	// PrivateClaims holds every claim this package does not model,
	// keyed by label, with its decoded value.
	PrivateClaims map[ClaimKey]corecbor.Value

	// ReceivedClaims holds claims kept exactly as received because
	// Encode couldn't otherwise write them back unchanged: a key that
	// is a bignum with an integer value (ErrAmbiguousClaimKey; its
	// ClaimKey.Raw is the key's received bytes), or a key or value
	// holding a NaN other than f97e00 (ErrNonCanonicalNaN). Decoding
	// fills it only with DecodeOptions.KeepAsReceived. Encode writes
	// each key and value verbatim, so for these claims its output is
	// the input, not Core Deterministic. Delete an entry to drop the
	// claim.
	ReceivedClaims map[ClaimKey]corecbor.RawMessage
}

// ContainsAudience reports whether s is the aud claim or one of its
// elements.
func (c *ClaimsSet) ContainsAudience(s string) bool {
	return c.Audience == s || slices.Contains(c.Audiences, s)
}

// Encode serializes the ClaimsSet as a CBOR map using CoreDeterministic mode.
// Claims in ReceivedClaims are written verbatim. A value holding a NaN
// other than f97e00 is an error wrapping ErrNonCanonicalNaN, since
// deterministic encoding would replace it.
//
// A claim emitted from more than one place (a modeled field, Private,
// PrivateClaims) must have the same value everywhere; otherwise Encode
// returns an error wrapping ErrMalformedClaims (v0.2.2 emitted a map
// with duplicate keys).
func (c *ClaimsSet) Encode() ([]byte, error) {
	v, err := c.toValue()
	if err != nil {
		return nil, err
	}
	// Never rewrite a NaN payload silently (ReceivedClaims are spliced
	// verbatim and not inspected here).
	if asreceived.NonCanonicalNaN(v) {
		return nil, fmt.Errorf("%w: %w: a claim holds a NaN other than f97e00; keep it in ReceivedClaims as encoded bytes", ErrMalformedClaims, ErrNonCanonicalNaN)
	}
	return claimsEncoder.Encode(nil, v)
}

// claimsEncoder writes claim sets. Non-finite floats are allowed: ±Inf
// and the quiet NaN f97e00 encode exactly, and decoding rejects (or,
// with KeepAsReceived, keeps verbatim) any other NaN.
var claimsEncoder = corecbor.NewShared(corecbor.ModeCoreDeterministic, corecbor.AllowNonFiniteFloats())

// claimsBuilder collects claims, rejecting conflicting duplicates.
type claimsBuilder struct {
	entries []corecbor.MapEntry
	index   map[ClaimKey]int
}

func (b *claimsBuilder) add(key ClaimKey, kv, val corecbor.Value) error {
	if b.index == nil {
		b.index = map[ClaimKey]int{}
	}
	if i, ok := b.index[key]; ok {
		if valuesEqual(b.entries[i].Value, val) {
			return nil
		}
		return claimErr(key, "claim set more than once with different values", nil)
	}
	b.index[key] = len(b.entries)
	b.entries = append(b.entries, corecbor.MapEntry{Key: kv, Value: val})
	return nil
}

func (b *claimsBuilder) addInt(n int64, val corecbor.Value) error {
	return b.add(IntKey(n), intValue(n), val)
}

func valuesEqual(a, b corecbor.Value) bool {
	ea, err1 := keyEncoder.Encode(nil, a)
	eb, err2 := keyEncoder.Encode(nil, b)
	return err1 == nil && err2 == nil && bytes.Equal(ea, eb)
}

func (c *ClaimsSet) toValue() (corecbor.Value, error) {
	var b claimsBuilder

	if c.Issuer != "" {
		if err := b.addInt(ClaimIss, corecbor.Text(c.Issuer)); err != nil {
			return corecbor.Value{}, err
		}
	}
	if c.Subject != "" {
		if err := b.addInt(ClaimSub, corecbor.Text(c.Subject)); err != nil {
			return corecbor.Value{}, err
		}
	}
	if aud, ok, err := c.audienceValue(); err != nil {
		return corecbor.Value{}, err
	} else if ok {
		if err := b.addInt(ClaimAud, aud); err != nil {
			return corecbor.Value{}, err
		}
	}
	for _, d := range []struct {
		key int64
		t   time.Time
	}{{ClaimExp, c.Expiration}, {ClaimNbf, c.NotBefore}, {ClaimIat, c.IssuedAt}} {
		if !d.t.IsZero() {
			if err := b.addInt(d.key, numericDate(d.t)); err != nil {
				return corecbor.Value{}, err
			}
		}
	}
	if len(c.CWTID) > 0 {
		if err := b.addInt(ClaimCti, corecbor.Bytes(c.CWTID)); err != nil {
			return corecbor.Value{}, err
		}
	}
	if c.Confirmation != nil {
		cnfMap, err := encodeCnf(c.Confirmation)
		if err != nil {
			return corecbor.Value{}, claimErr(IntKey(ClaimCnf), "cnf", err)
		}
		if err := b.addInt(ClaimCnf, corecbor.MakeMapFromSlice(cnfMap)); err != nil {
			return corecbor.Value{}, err
		}
	}
	if s := c.Scope; s != nil {
		v := corecbor.Bytes(s.Bytes)
		if s.IsText {
			v = corecbor.Text(s.Text)
		}
		if err := b.addInt(ClaimScope, v); err != nil {
			return corecbor.Value{}, err
		}
	}
	if c.ACEProfile != nil {
		if err := b.addInt(ClaimACEProfile, intValue(*c.ACEProfile)); err != nil {
			return corecbor.Value{}, err
		}
	}
	if c.CNonce != nil {
		if err := b.addInt(ClaimCNonce, corecbor.Bytes(c.CNonce)); err != nil {
			return corecbor.Value{}, err
		}
	}
	if c.Exi != nil {
		if err := b.addInt(ClaimExi, corecbor.Uint(*c.Exi)); err != nil {
			return corecbor.Value{}, err
		}
	}

	for k, v := range c.Private {
		kv, err := toValue(k)
		if err != nil {
			return corecbor.Value{}, fmt.Errorf("%w: private claim key: %w", ErrMalformedClaims, err)
		}
		if !isClaimLabel(kv) {
			return corecbor.Value{}, fmt.Errorf("%w: private claim key %v (%T) is not an integer or a text string", ErrMalformedClaims, k, k)
		}
		val, err := toValue(v)
		if err != nil {
			return corecbor.Value{}, fmt.Errorf("%w: private claim value: %w", ErrMalformedClaims, err)
		}
		if err := b.add(claimKeyOf(kv), kv, val); err != nil {
			return corecbor.Value{}, err
		}
	}
	for k, v := range c.PrivateClaims {
		kv, err := k.value()
		if err != nil {
			return corecbor.Value{}, claimErr(k, "private claim key", err)
		}
		if !isClaimLabel(kv) {
			return corecbor.Value{}, claimErr(k, "private claim key is not an integer or a text string", nil)
		}
		if err := b.add(k, kv, v); err != nil {
			return corecbor.Value{}, err
		}
	}
	for k, raw := range c.ReceivedClaims {
		kv, err := k.receivedValue()
		if err != nil {
			return corecbor.Value{}, claimErr(k, "received claim key", err)
		}
		if !asreceived.OneItem(raw) {
			return corecbor.Value{}, claimErr(k, "received claim value is not one CBOR data item", nil)
		}
		if err := b.add(k, kv, rawvalue.Make(raw)); err != nil {
			return corecbor.Value{}, err
		}
	}
	return corecbor.MakeMapFromSlice(b.entries), nil
}

func (c *ClaimsSet) audienceValue() (corecbor.Value, bool, error) {
	switch len(c.Audiences) {
	case 0:
		if c.Audience == "" {
			return corecbor.Value{}, false, nil
		}
		return corecbor.Text(c.Audience), true, nil
	case 1:
		if c.Audience != "" && c.Audience != c.Audiences[0] {
			return corecbor.Value{}, false, claimErr(IntKey(ClaimAud), "Audience and Audiences disagree", nil)
		}
		return corecbor.Text(c.Audiences[0]), true, nil
	default:
		if c.Audience != "" && !slices.Contains(c.Audiences, c.Audience) {
			return corecbor.Value{}, false, claimErr(IntKey(ClaimAud), "Audience is not one of Audiences", nil)
		}
		items := make([]corecbor.Value, len(c.Audiences))
		for i, a := range c.Audiences {
			items[i] = corecbor.Text(a)
		}
		return corecbor.MakeArrayFromSlice(items), true, nil
	}
}

// DecodeOptions adjusts claims decoding. The zero value is exactly
// DecodeClaimsSet's behavior.
type DecodeOptions struct {
	// RejectUnknownCnf rejects cnf members other than 1, 2 and 3.
	// Opt-in; DecodeClaimsSet ignores them, as in v0.2.2.
	RejectUnknownCnf bool

	// KeepAsReceived keeps claims that Encode couldn't write back
	// unchanged in ClaimsSet.ReceivedClaims, byte for byte, instead of
	// rejecting them: a claim key that is a bignum with an integer value
	// (ErrAmbiguousClaimKey), and a claim whose key or value holds a
	// NaN other than f97e00 (ErrNonCanonicalNaN). A modeled claim (iss,
	// sub, aud, exp, nbf, iat, cti, cnf) is still rejected, whether its
	// key is the integer or a bignum with that value. Opt-in;
	// without it, and in ClaimsFromHeaders, these claims are errors.
	KeepAsReceived bool

	// AllowDuplicateClaims restores v0.2's last-one-wins handling of
	// duplicate map keys.
	//
	// Deprecated: duplicate claims make exp and nbf ambiguous (RFC 8392
	// §7.2); removed no earlier than v0.32.0.
	AllowDuplicateClaims bool
}

// DecodeClaimsSet deserializes a CBOR-encoded claims map into a ClaimsSet.
//
// It rejects duplicate map keys (RFC 8392 §7.2) and claim keys that
// are not integers or text strings (RFC 8392 §3), and bounds decode
// memory. It never panics on malformed input. Errors wrap
// ErrMalformedClaims and, where there is one, the underlying corecbor
// error; errors about one claim are *ClaimError.
func DecodeClaimsSet(data []byte) (*ClaimsSet, error) {
	return DecodeClaimsSetWith(data, DecodeOptions{})
}

// DecodeClaimsSetWith is DecodeClaimsSet with options.
func DecodeClaimsSetWith(data []byte, opts DecodeOptions) (*ClaimsSet, error) {
	dopts := []corecbor.DecoderOption{corecbor.WithoutInternalArena(), corecbor.WithMemoryBudget(decodeBudget)}
	if !opts.AllowDuplicateClaims {
		dopts = append(dopts, corecbor.RejectDuplicateMapKeys())
	}
	v, err := corecbor.NewDecoder(dopts...).Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	var spans []asreceived.Span
	if opts.KeepAsReceived {
		if spans, err = asreceived.MapSpans(data); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
		}
	}
	return decodeClaimsValue(v, spans, opts)
}

// decodeClaimsValue decodes the claims map v. spans, when not nil, are
// the source bytes of v's entries (DecodeOptions.KeepAsReceived).
func decodeClaimsValue(v corecbor.Value, spans []asreceived.Span, opts DecodeOptions) (*ClaimsSet, error) {
	if v.Kind != corecbor.KindMap {
		return nil, fmt.Errorf("%w: expected map, got kind %d", ErrMalformedClaims, v.Kind)
	}
	if spans != nil && len(spans) != len(v.Map()) {
		// Only with the deprecated AllowDuplicateClaims, which drops
		// the earlier duplicates.
		return nil, fmt.Errorf("%w: duplicate claims can't be kept as received", ErrMalformedClaims)
	}

	cs := &ClaimsSet{}
	for i, entry := range v.Map() {
		// A bignum with an integer value has its own error and may be
		// kept (KeepAsReceived); any other non-label key is malformed.
		if !isClaimLabel(entry.Key) && !asreceived.IntegerBignum(entry.Key) {
			return nil, claimErr(claimKeyOf(entry.Key), "claim key must be an integer or a text string (RFC 8392 §3)", nil)
		}
		kept, err := cs.keepAsReceived(entry, spans, i)
		if err != nil {
			return nil, err
		}
		if kept {
			continue
		}
		key := claimKeyOf(entry.Key)
		if handled, err := cs.decodeRegistered(key, entry.Value, opts); err != nil {
			return nil, err
		} else if handled {
			continue
		}
		cs.addPrivate(key, entry.Value)
	}
	return cs, nil
}

// keepAsReceived handles a claim Encode couldn't write back unchanged.
// With spans it is kept in ReceivedClaims, unless it is a modeled claim
// (whose value is parsed and checked); otherwise it is an error.
func (cs *ClaimsSet) keepAsReceived(entry corecbor.MapEntry, spans []asreceived.Span, i int) (bool, error) {
	ambiguous := asreceived.IntegerBignum(entry.Key)
	nan := asreceived.NonCanonicalNaN(entry.Key) || asreceived.NonCanonicalNaN(entry.Value)
	if !ambiguous && !nan {
		return false, nil
	}
	key := claimKeyOf(entry.Key)
	if ambiguous {
		key = receivedKey(entry.Key)
	}
	// A modeled claim is never kept: by its key, or, for an ambiguous
	// key, by the integer it stands for (bignum 5 is nbf to a peer).
	modeled := !ambiguous && modeledClaim(key)
	if n, ok := asreceived.BignumInt64(entry.Key); ok && modeledClaim(IntKey(n)) {
		modeled = true
	}
	if spans == nil || modeled {
		if ambiguous {
			return false, ambiguousKeyErr(entry.Key)
		}
		return false, &ClaimError{Key: key, Err: fmt.Errorf("%w: %w", ErrMalformedClaims, ErrNonCanonicalNaN)}
	}
	if key.Raw != "" {
		key = ClaimKey{Raw: string(spans[i].Key)} // the key exactly as received
	}
	if cs.ReceivedClaims == nil {
		cs.ReceivedClaims = map[ClaimKey]corecbor.RawMessage{}
	}
	cs.ReceivedClaims[key] = bytes.Clone(spans[i].Value)
	return true, nil
}

// modeledClaim reports whether decodeRegistered parses key into a typed
// field and checks its value; such a claim is never kept as received.
func modeledClaim(key ClaimKey) bool {
	if key.Raw != "" || key.IsText {
		return false
	}
	switch key.Int {
	case ClaimIss, ClaimSub, ClaimAud, ClaimExp, ClaimNbf, ClaimIat, ClaimCti, ClaimCnf:
		return true
	}
	return false
}

// decodeRegistered decodes a claim this package models. It reports
// whether key was handled; unhandled claims go to the private maps.
func (cs *ClaimsSet) decodeRegistered(key ClaimKey, val corecbor.Value, opts DecodeOptions) (bool, error) {
	if key.Raw != "" || key.IsText {
		return false, nil
	}
	switch key.Int {
	case ClaimIss:
		if val.Kind != corecbor.KindText {
			return true, claimErr(key, "iss must be text", nil)
		}
		cs.Issuer = val.TextVal()
	case ClaimSub:
		if val.Kind != corecbor.KindText {
			return true, claimErr(key, "sub must be text", nil)
		}
		cs.Subject = val.TextVal()
	case ClaimAud:
		if err := cs.decodeAudience(val); err != nil {
			return true, err
		}
	case ClaimExp, ClaimNbf, ClaimIat:
		ts, err := parseNumericDate(val)
		if err == nil {
			err = checkPresentDate(ts, val)
		}
		if err != nil {
			return true, &ClaimError{Key: key, Err: err}
		}
		switch key.Int {
		case ClaimExp:
			cs.Expiration = ts
		case ClaimNbf:
			cs.NotBefore = ts
		default:
			cs.IssuedAt = ts
		}
	case ClaimCti:
		if val.Kind != corecbor.KindBytes {
			return true, claimErr(key, "cti must be bytes", nil)
		}
		cs.CWTID = val.BytesVal()
	case ClaimCnf:
		cnf, err := decodeCnf(val, opts)
		if err != nil {
			return true, claimErr(key, "cnf", err)
		}
		cs.Confirmation = cnf
	case ClaimScope, ClaimACEProfile, ClaimCNonce, ClaimExi:
		// v0.2.2 kept these in Private; they stay there and also fill
		// their typed field. An ill-typed value is an error naming the
		// claim (RFC 9200 §5.10, 037 W21): kept as a private claim it
		// would silently not be applied.
		if !cs.decodeACE(key.Int, val) {
			return true, claimErr(key, aceTypes[key.Int], nil)
		}
		cs.addPrivateCompat(key, val)
	default:
		return false, nil
	}
	return true, nil
}

func (cs *ClaimsSet) decodeAudience(val corecbor.Value) error {
	key := IntKey(ClaimAud)
	switch val.Kind {
	case corecbor.KindText:
		cs.Audience = val.TextVal()
		cs.Audiences = []string{cs.Audience}
	case corecbor.KindArray:
		items := val.Array()
		if len(items) == 0 {
			return claimErr(key, "aud array must not be empty", nil)
		}
		cs.Audiences = make([]string, len(items))
		for i, it := range items {
			if it.Kind != corecbor.KindText {
				return claimErr(key, "aud array elements must be text", nil)
			}
			cs.Audiences[i] = it.TextVal()
		}
	default:
		return claimErr(key, "aud must be text or an array of text", nil)
	}
	return nil
}

// aceTypes describes the type each RFC 9200 claim must have.
var aceTypes = map[int64]string{
	ClaimScope:      "scope must be text or bytes",
	ClaimACEProfile: "ace_profile must be an integer",
	ClaimCNonce:     "cnonce must be bytes",
	ClaimExi:        "exi must be an unsigned integer",
}

func (cs *ClaimsSet) decodeACE(n int64, val corecbor.Value) bool {
	switch n {
	case ClaimScope:
		switch val.Kind {
		case corecbor.KindText:
			cs.Scope = &Scope{Text: val.TextVal(), IsText: true}
		case corecbor.KindBytes:
			cs.Scope = &Scope{Bytes: val.BytesVal()}
		default:
			return false
		}
	case ClaimACEProfile:
		k := claimKeyOf(val) // integer range check
		if (val.Kind != corecbor.KindUint && val.Kind != corecbor.KindNegInt) || k.Raw != "" {
			return false
		}
		p := k.Int
		cs.ACEProfile = &p
	case ClaimCNonce:
		if val.Kind != corecbor.KindBytes {
			return false
		}
		cs.CNonce = val.BytesVal()
	case ClaimExi:
		e, err := val.Uint64()
		if err != nil {
			return false
		}
		cs.Exi = &e
	}
	return true
}

// addPrivate records an unmodeled claim in PrivateClaims and, when its
// key is representable there, in the deprecated Private map.
func (cs *ClaimsSet) addPrivate(key ClaimKey, val corecbor.Value) {
	cs.addPrivateTyped(key, val)
	cs.addPrivateCompat(key, val)
}

func (cs *ClaimsSet) addPrivateTyped(key ClaimKey, val corecbor.Value) {
	if cs.PrivateClaims == nil {
		cs.PrivateClaims = make(map[ClaimKey]corecbor.Value)
	}
	cs.PrivateClaims[key] = val
}

func (cs *ClaimsSet) addPrivateCompat(key ClaimKey, val corecbor.Value) {
	if key.Raw != "" {
		return // not hashable as a Go map key in v0.2.2's form
	}
	if cs.Private == nil {
		cs.Private = make(map[any]any)
	}
	if key.IsText {
		cs.Private[key.Text] = fromValue(val)
	} else {
		cs.Private[key.Int] = fromValue(val)
	}
}

func toValue(v any) (corecbor.Value, error) {
	switch x := v.(type) {
	case corecbor.Value:
		return x, nil
	case string:
		return corecbor.Text(x), nil
	case int:
		return intValue(int64(x)), nil
	case int64:
		return intValue(x), nil
	case uint64:
		return corecbor.Uint(x), nil
	case float64:
		return corecbor.Float64(x), nil
	case []byte:
		return corecbor.Bytes(x), nil
	case bool:
		return corecbor.Bool(x), nil
	default:
		return corecbor.Value{}, fmt.Errorf("%w: unsupported type %T", ErrMalformedClaims, v)
	}
}

// fromValue converts a decoded private claim value to the Go form
// Private holds. Integers outside the int64 range stay corecbor.Value
// rather than wrapping.
func fromValue(v corecbor.Value) any {
	switch v.Kind {
	case corecbor.KindUint, corecbor.KindNegInt:
		n, err := v.Int64()
		if err != nil {
			return v
		}
		return n
	case corecbor.KindText:
		return v.TextVal()
	case corecbor.KindBytes:
		return v.BytesVal()
	case corecbor.KindFloat64:
		return v.Float64Val()
	case corecbor.KindFloat32:
		return float64(v.Float32Val())
	case corecbor.KindBool:
		return v.BoolVal()
	default:
		return v
	}
}

func encodeCnf(cnf *Confirmation) ([]corecbor.MapEntry, error) {
	if key, enc, _ := cnf.members(); key && enc {
		return nil, fmt.Errorf("%w: %s", errCnf, errTwoKeys)
	}
	var m []corecbor.MapEntry
	if cnf.Key != nil {
		kv, err := cnfKeyValue(cnf.Key)
		if err != nil {
			return nil, err
		}
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(cnfKeyByCOSEKey), Value: kv})
	}
	switch {
	case cnf.EncryptedKey != nil:
		ev, err := encryptedKeyValue(cnf.EncryptedKey)
		if err != nil {
			return nil, err
		}
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(cnfKeyEncrypted), Value: ev})
	case len(cnf.Encrypted) > 0:
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(cnfKeyEncrypted), Value: corecbor.Bytes(cnf.Encrypted)})
	}
	if len(cnf.KeyID) > 0 {
		m = append(m, corecbor.MapEntry{Key: corecbor.Uint(cnfKeyByKid), Value: corecbor.Bytes(cnf.KeyID)})
	}
	return m, nil
}

// cnfKeyValue encodes the cnf COSE_Key. Asymmetric keys are reduced to
// their public parameters, as in v0.2.2, so a signing key passed by
// mistake doesn't leak its private part. A symmetric key is emitted as
// is, since Encode also produces the plaintext Seal encrypts; RFC 8747
// §3.2 allows it only in an encrypted CWT, so Sign, MAC and
// SetClaimsHeader refuse it (checkNotExposed).
func cnfKeyValue(k *cose.Key) (corecbor.Value, error) {
	if k.KeyType() != cose.KeyTypeSymmetric {
		pub, err := k.Public()
		if err != nil {
			return corecbor.Value{}, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
		}
		k = pub
	}
	b, err := k.MarshalCBOR()
	if err != nil {
		return corecbor.Value{}, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	return keyDecoder().Decode(b)
}

// encryptedKeyValue encodes an Encrypted_COSE_Key as the untagged
// COSE_Encrypt0/COSE_Encrypt array RFC 8747 §3.3 shows.
func encryptedKeyValue(ek *EncryptedKey) (corecbor.Value, error) {
	var b []byte
	var err error
	switch {
	case ek.Encrypt0 != nil && ek.Encrypt == nil:
		b, err = cose.MarshalEncrypt0(ek.Encrypt0)
	case ek.Encrypt != nil && ek.Encrypt0 == nil:
		b, err = cose.MarshalEncrypt(ek.Encrypt)
	default:
		return corecbor.Value{}, fmt.Errorf("%w: EncryptedKey must set exactly one of Encrypt0, Encrypt", ErrMalformedClaims)
	}
	if err != nil {
		return corecbor.Value{}, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	v, err := keyDecoder().Decode(b)
	if err != nil {
		return corecbor.Value{}, fmt.Errorf("%w: %w", ErrMalformedClaims, err)
	}
	if v.Kind == corecbor.KindTag {
		v = v.TagInner()
	}
	return v, nil
}

var errCnf = errors.New("cnf")

func decodeCnf(v corecbor.Value, opts DecodeOptions) (*Confirmation, error) {
	if v.Kind != corecbor.KindMap {
		return nil, fmt.Errorf("%w: expected map, got kind %d", errCnf, v.Kind)
	}
	cnf := &Confirmation{}
	keys := 0 // COSE_Key and Encrypted_COSE_Key members seen
	for _, entry := range v.Map() {
		k := claimKeyOf(entry.Key)
		if k.Raw != "" || k.IsText || k.Int < cnfKeyByCOSEKey || k.Int > cnfKeyByKid {
			if opts.RejectUnknownCnf {
				return nil, fmt.Errorf("%w: unknown member %s", errCnf, k)
			}
			continue
		}
		if k.Int != cnfKeyByKid {
			keys++
		}
		switch k.Int {
		case cnfKeyByCOSEKey:
			if entry.Value.Kind != corecbor.KindMap {
				return nil, fmt.Errorf("%w: COSE_Key must be map", errCnf)
			}
			key, err := decodeCnfKey(entry.Value)
			if err != nil {
				return nil, err
			}
			cnf.Key = key
		case cnfKeyEncrypted:
			if err := decodeCnfEncrypted(cnf, entry.Value); err != nil {
				return nil, err
			}
		case cnfKeyByKid:
			if entry.Value.Kind != corecbor.KindBytes {
				return nil, fmt.Errorf("%w: kid must be bytes", errCnf)
			}
			cnf.KeyID = entry.Value.BytesVal()
		}
	}
	if keys > 1 {
		// RFC 8747 §3.1: a kid may accompany the key.
		return nil, fmt.Errorf("%w: %s", errCnf, errTwoKeys)
	}
	return cnf, nil
}

func decodeCnfKey(v corecbor.Value) (*cose.Key, error) {
	b, err := keyEncoder.Encode(nil, v)
	if err != nil {
		return nil, fmt.Errorf("%w: COSE_Key: %w", errCnf, err)
	}
	// Short EC2 coordinates are left-padded as in v0.2.2; oversize ones,
	// OKP keys without crv and off-curve points are rejected (proposal
	// 028, RFC 9053 §7).
	k, err := cose.ParseKey(b, cose.AllowShortCoordinates())
	if err != nil {
		return nil, fmt.Errorf("%w: COSE_Key: %w", errCnf, err)
	}
	return k, nil
}

func decodeCnfEncrypted(cnf *Confirmation, v corecbor.Value) error {
	switch v.Kind {
	case corecbor.KindBytes:
		cnf.Encrypted = v.BytesVal()
		return nil
	case corecbor.KindArray, corecbor.KindTag:
	default:
		return fmt.Errorf("%w: encrypted key must be bytes or a COSE_Encrypt0/COSE_Encrypt", errCnf)
	}
	b, err := keyEncoder.Encode(nil, v)
	if err != nil {
		return fmt.Errorf("%w: encrypted key: %w", errCnf, err)
	}
	inner := v
	if inner.Kind == corecbor.KindTag {
		inner = inner.TagInner()
	}
	ek := &EncryptedKey{}
	switch {
	case inner.Kind == corecbor.KindArray && len(inner.Array()) == 3:
		ek.Encrypt0, err = cose.UnmarshalEncrypt0(b)
	case inner.Kind == corecbor.KindArray && len(inner.Array()) == 4:
		ek.Encrypt, err = cose.UnmarshalEncrypt(b)
	default:
		return fmt.Errorf("%w: encrypted key is not a COSE_Encrypt0 or COSE_Encrypt", errCnf)
	}
	if err != nil {
		return fmt.Errorf("%w: encrypted key: %w", errCnf, err)
	}
	cnf.Encrypted = b
	cnf.EncryptedKey = ek
	return nil
}
