// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"fmt"
	"slices"

	"github.com/jahkeup/corecbor"
)

// Countersignature header labels (RFC 9338 §2). Both go in the
// unprotected bucket of the layer they countersign.
const (
	// HeaderCountersignature (11) holds one or more full V2
	// countersignatures (COSE_Countersignature).
	HeaderCountersignature int64 = 11
	// HeaderCountersignature0 (12) holds an abbreviated V2
	// countersignature (COSE_Countersignature0): the signature bytes,
	// with algorithm and key known from context.
	HeaderCountersignature0 int64 = 12
)

// Countersignature is a full V2 countersignature (COSE_Countersignature,
// RFC 9338 §3.1), which has the structure of a COSE_Signature.
type Countersignature struct {
	Protected   Headers
	Unprotected Headers
	Signature   []byte
}

// CountersignTarget is a message a countersignature can cover: *Sign1,
// *Sign, *Mac0, *Mac, *Encrypt0 or *Encrypt (RFC 9338 §3.3). The
// countersignature covers the message's protected bucket, its payload
// (the ciphertext, for encrypted messages) and, for COSE_Sign1 and the
// MAC messages, its signature or tag.
type CountersignTarget interface {
	countersignLayer() csLayer
}

// csLayer is the part of a target the Countersign_structure covers.
type csLayer struct {
	prot, unprot *Headers
	payload      []byte
	other        [][]byte // bstr fields after the second (RFC 9338 §3.3)
	finished     bool     // the target's own signature or tag is present
}

func (m *Sign1) countersignLayer() csLayer {
	return csLayer{&m.Protected, &m.Unprotected, m.Payload, [][]byte{m.Signature}, len(m.Signature) > 0}
}

func (m *Sign) countersignLayer() csLayer {
	return csLayer{&m.Protected, &m.Unprotected, m.Payload, nil, len(m.Signatures) > 0}
}

func (m *Mac0) countersignLayer() csLayer {
	return csLayer{&m.Protected, &m.Unprotected, m.Payload, [][]byte{m.Tag}, len(m.Tag) > 0}
}

func (m *Mac) countersignLayer() csLayer {
	return csLayer{&m.Protected, &m.Unprotected, m.Payload, [][]byte{m.Tag}, len(m.Tag) > 0}
}

func (m *Encrypt0) countersignLayer() csLayer {
	return csLayer{&m.Protected, &m.Unprotected, m.Ciphertext, nil, true}
}

func (m *Encrypt) countersignLayer() csLayer {
	return csLayer{&m.Protected, &m.Unprotected, m.Ciphertext, nil, true}
}

// check returns the layer ready for countersigning or verification: the
// payload attached, the target finished, and labels 11 and 12 only in
// the unprotected bucket.
func (l csLayer) check() error {
	for _, label := range []int64{HeaderCountersignature, HeaderCountersignature0} {
		if _, ok := l.prot.params[label]; ok {
			return fmt.Errorf("%w: countersignature label %d in the protected bucket (RFC 9338 §2)", ErrMalformed, label)
		}
	}
	if l.payload == nil {
		return ErrMissingPayload
	}
	if !l.finished {
		return fmt.Errorf("%w: the target has no signature or tag yet; countersign it after it is finished (RFC 9338 §3.3)", ErrMalformed)
	}
	return nil
}

// countersignTBS encodes a Countersign_structure (RFC 9338 §3.3).
// signProtected is nil for an abbreviated countersignature.
func countersignTBS(enc *corecbor.Encoder, abbreviated bool, body, signProtected, external []byte, l csLayer) ([]byte, error) {
	ctx := "CounterSignature"
	if abbreviated {
		ctx = "CounterSignature0"
	}
	if l.other != nil {
		ctx += "V2"
	}
	bs := func(b []byte) corecbor.Value {
		if b == nil {
			b = []byte{}
		}
		return corecbor.Bytes(b)
	}
	elems := []corecbor.Value{corecbor.Text(ctx), bs(body)}
	if !abbreviated {
		elems = append(elems, bs(signProtected))
	}
	elems = append(elems, bs(external), bs(l.payload))
	if l.other != nil {
		other := make([]corecbor.Value, len(l.other))
		for i, o := range l.other {
			other[i] = bs(o)
		}
		elems = append(elems, corecbor.MakeArrayFromSlice(other))
	}
	return enc.Encode(nil, corecbor.MakeArrayFromSlice(elems))
}

// Countersign adds a full V2 countersignature by s to target (RFC 9338
// §3.1): a COSE_Countersignature carrying the Signer's headers, appended
// to the target's unprotected label 11. The target must be finished
// (signed, MACed or encrypted) and its payload or ciphertext attached
// (ErrMissingPayload otherwise). The Signer's external AAD is used.
// Countersigning doesn't change the target's own signature or tag.
func (s *Signer) Countersign(target CountersignTarget) error {
	return s.CountersignContext(context.Background(), target)
}

// CountersignContext is Countersign with a context, passed to the key
// when it implements ContextSigner.
func (s *Signer) CountersignContext(ctx context.Context, target CountersignTarget) error {
	l := target.countersignLayer()
	if err := l.check(); err != nil {
		return err
	}
	body, err := l.prot.encodeProtected()
	if err != nil {
		return err
	}
	tbs, err := countersignTBS(s.enc, false, body, s.protectedBytes, s.external, l)
	if err != nil {
		return err
	}
	sig, err := s.signBytes(ctx, s.alg, tbs)
	if err != nil {
		return err
	}
	unprot, err := (&Headers{params: s.unprotected}).toCBORMap()
	if err != nil {
		return err
	}
	prot := s.protectedBytes
	if prot == nil {
		prot = []byte{}
	}
	cs := corecbor.MakeArray(corecbor.Bytes(prot), unprot, corecbor.Bytes(sig))

	// Keep existing countersignatures exactly as they are.
	switch v, ok := l.unprot.params[HeaderCountersignature]; {
	case !ok:
		l.unprot.put(HeaderCountersignature, cs)
	default:
		cur, ok := v.(corecbor.Value)
		if !ok || cur.Kind != corecbor.KindArray || len(cur.Items) == 0 {
			return fmt.Errorf("%w: existing label 11 is not a countersignature", ErrMalformed)
		}
		var items []corecbor.Value
		if cur.Items[0].Kind == corecbor.KindBytes {
			items = []corecbor.Value{cur, cs} // one COSE_Countersignature
		} else {
			items = append(slices.Clone(cur.Items), cs)
		}
		l.unprot.put(HeaderCountersignature, corecbor.MakeArrayFromSlice(items))
	}
	return nil
}

// Countersign0 adds an abbreviated V2 countersignature by s to target
// (RFC 9338 §3.2): the signature alone, in the target's unprotected
// label 12. The Signer's headers aren't carried, so the verifier must
// know the key and algorithm from context. A target holds at most one;
// a second is ErrUnsupportedHeader. Otherwise as Countersign.
func (s *Signer) Countersign0(target CountersignTarget) error {
	return s.Countersign0Context(context.Background(), target)
}

// Countersign0Context is Countersign0 with a context.
func (s *Signer) Countersign0Context(ctx context.Context, target CountersignTarget) error {
	l := target.countersignLayer()
	if err := l.check(); err != nil {
		return err
	}
	if _, ok := l.unprot.params[HeaderCountersignature0]; ok {
		return fmt.Errorf("%w: the target already has an abbreviated countersignature (label 12)", ErrUnsupportedHeader)
	}
	body, err := l.prot.encodeProtected()
	if err != nil {
		return err
	}
	tbs, err := countersignTBS(s.enc, true, body, nil, s.external, l)
	if err != nil {
		return err
	}
	sig, err := s.signBytes(ctx, s.alg, tbs)
	if err != nil {
		return err
	}
	l.unprot.put(HeaderCountersignature0, sig)
	return nil
}

// Countersignatures returns target's full V2 countersignatures (label
// 11, RFC 9338 §2), in order; none is (nil, nil). They aren't verified;
// use Verifier.VerifyCountersignature. A malformed label 11, or one in
// the protected bucket, is ErrMalformed.
func Countersignatures(target CountersignTarget) ([]Countersignature, error) {
	l := target.countersignLayer()
	if _, ok := l.prot.params[HeaderCountersignature]; ok {
		return nil, fmt.Errorf("%w: countersignature label 11 in the protected bucket (RFC 9338 §2)", ErrMalformed)
	}
	v, ok := l.unprot.params[HeaderCountersignature]
	if !ok {
		return nil, nil
	}
	val, ok := v.(corecbor.Value)
	if !ok || val.Kind != corecbor.KindArray || len(val.Items) == 0 {
		return nil, fmt.Errorf("%w: label 11 must be a COSE_Countersignature or a non-empty array of them", ErrMalformed)
	}
	items := []corecbor.Value{val}
	if val.Items[0].Kind != corecbor.KindBytes {
		items = val.Items
	}
	out := make([]Countersignature, len(items))
	for i, it := range items {
		cs, err := parseCountersignature(it)
		if err != nil {
			return nil, fmt.Errorf("countersignature %d: %w", i, err)
		}
		out[i] = cs
	}
	return out, nil
}

func parseCountersignature(v corecbor.Value) (Countersignature, error) {
	if v.Kind != corecbor.KindArray || len(v.Items) != 3 ||
		v.Items[0].Kind != corecbor.KindBytes || v.Items[2].Kind != corecbor.KindBytes {
		return Countersignature{}, fmt.Errorf("%w: COSE_Countersignature must be [bstr, map, bstr]", ErrMalformed)
	}
	prot, unprot, err := decodeBuckets(v.Items[0].BytesVal(), v.Items[1], DecodeLimits{})
	if err != nil {
		return Countersignature{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return Countersignature{Protected: *prot, Unprotected: *unprot, Signature: v.Items[2].BytesVal()}, nil
}

// VerifyCountersignature verifies one full countersignature of target
// (from Countersignatures) with v's key, under v's policy for the
// countersignature's headers (alg binding, crit, allowed algorithms)
// and v's external AAD. It doesn't verify the target itself. The
// target's crit is checked as Verify checks it; a crit can't list
// labels 11 or 12, which are unprotected (RFC 9338 §2).
func (v *Verifier) VerifyCountersignature(target CountersignTarget, cs Countersignature) error {
	l := target.countersignLayer()
	if err := l.check(); err != nil {
		return err
	}
	if err := checkCrit(l.prot, l.unprot, &v.policy); err != nil {
		return err
	}
	alg, err := v.checkLayer(&cs.Protected, &cs.Unprotected)
	if err != nil {
		return err
	}
	body, err := l.prot.authProtected(&v.policy)
	if err != nil {
		return err
	}
	signProt, err := cs.Protected.authProtected(&v.policy)
	if err != nil {
		return err
	}
	tbs, err := countersignTBS(v.enc, false, body, signProt, v.external, l)
	if err != nil {
		return err
	}
	return v.verifyBytes(alg, tbs, cs.Signature)
}

// VerifyCountersignature0 verifies target's abbreviated countersignature
// (label 12) with v's key. With no headers to name it, the algorithm is
// the one v's key implies; for an RSA key, WithAllowedAlgorithms must
// list exactly one. A target without label 12 is ErrVerification.
func (v *Verifier) VerifyCountersignature0(target CountersignTarget) error {
	l := target.countersignLayer()
	if err := l.check(); err != nil {
		return err
	}
	if err := checkCrit(l.prot, l.unprot, &v.policy); err != nil {
		return err
	}
	raw, ok := l.unprot.params[HeaderCountersignature0]
	if !ok {
		return fmt.Errorf("%w: no abbreviated countersignature (label 12)", ErrVerification)
	}
	sig, ok := raw.([]byte)
	if !ok {
		return fmt.Errorf("%w: label 12 must be a bstr (RFC 9338 §3.2)", ErrMalformed)
	}
	alg := v.alg
	if alg == algRSAFamily {
		if len(v.policy.allowed) != 1 {
			return fmt.Errorf("%w: an abbreviated countersignature with an RSA key needs exactly one algorithm in WithAllowedAlgorithms", ErrAlgorithmMismatch)
		}
		alg = v.policy.allowed[0]
	} else if v.policy.allowed != nil && !slices.Contains(v.policy.allowed, alg) {
		return fmt.Errorf("%w: %s not in allowed algorithms", ErrAlgorithmMismatch, alg)
	}
	body, err := l.prot.authProtected(&v.policy)
	if err != nil {
		return err
	}
	tbs, err := countersignTBS(v.enc, true, body, nil, v.external, l)
	if err != nil {
		return err
	}
	return v.verifyBytes(alg, tbs, sig)
}
