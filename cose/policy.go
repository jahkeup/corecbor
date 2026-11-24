// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"fmt"
	"math"
	"slices"

	"github.com/jahkeup/corecbor"
)

// headerPolicy is the verification policy shared by the Sign, MAC and
// Encrypt paths (proposal 027 H2, H3).
type headerPolicy struct {
	allowed    []Algorithm // nil: the default for the path
	knownCrit  []any       // labels the caller processes (normalized)
	legacyAlg  bool        // v0.2.2: don't bind the header alg
	legacyCrit bool        // v0.2.2: ignore crit

	emptyAsReceived bool // Allow…EmptyProtectedAsReceived (037 S14)
}

// normalizeLabel converts a caller-supplied label to the form header
// maps use (int64 or string). ok is false for anything else.
func normalizeLabel(l any) (any, bool) {
	switch x := l.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case int32:
		return int64(x), true
	case uint64:
		if x > math.MaxInt64 {
			return nil, false
		}
		return int64(x), true
	case string:
		return x, true
	default:
		return nil, false
	}
}

func normalizeLabels(labels []any) []any {
	out := make([]any, 0, len(labels))
	for _, l := range labels {
		if n, ok := normalizeLabel(l); ok {
			out = append(out, n)
		}
	}
	return out
}

// algLocation says where a layer's alg header was found.
type algLocation int

const (
	algAbsent algLocation = iota
	algProtected
	algUnprotected
)

// headerAlg returns a layer's alg header and where it was. An alg that
// isn't an integer identifier, or that appears in both buckets, is
// ErrAlgorithmMismatch.
func headerAlg(prot, unprot *Headers) (Algorithm, algLocation, error) {
	pv, inProt := prot.params[headerLabelAlgorithm]
	uv, inUnprot := unprot.params[headerLabelAlgorithm]
	switch {
	case inProt && inUnprot:
		return 0, algAbsent, fmt.Errorf("%w: alg in both protected and unprotected buckets", ErrAlgorithmMismatch)
	case inProt:
		a, err := algValue(pv)
		return a, algProtected, err
	case inUnprot:
		a, err := algValue(uv)
		return a, algUnprotected, err
	default:
		return 0, algAbsent, nil
	}
}

func algValue(v any) (Algorithm, error) {
	switch a := v.(type) {
	case int64:
		return Algorithm(a), nil
	case Algorithm:
		return a, nil
	case int:
		return Algorithm(a), nil
	default:
		return 0, fmt.Errorf("%w: unsupported alg identifier %v", ErrAlgorithmMismatch, v)
	}
}

// bindAlg checks a layer's alg header against the algorithm implied by
// the key (or supplied by the caller): an alg in the protected bucket,
// or one only in the unprotected bucket, must equal want; with no alg
// the layer is verified as want. RFC 9052 §3.1 requires alg to be
// protected where changing it is an attack vector; an unprotected alg
// that must equal the key's own algorithm can't steer verification, so
// it is accepted (cose-wg sign1-tests/sign-pass-01). allowed, when set,
// must contain want.
func bindAlg(prot, unprot *Headers, want Algorithm, p *headerPolicy) error {
	if p.legacyAlg {
		return nil
	}
	a, loc, err := headerAlg(prot, unprot)
	if err != nil {
		return err
	}
	if loc != algAbsent && a != want {
		return fmt.Errorf("%w: header alg %s, key implies %s", ErrAlgorithmMismatch, a, want)
	}
	if p.allowed != nil && !slices.Contains(p.allowed, want) {
		return fmt.Errorf("%w: %s not in allowed algorithms", ErrAlgorithmMismatch, want)
	}
	return nil
}

// multiAlg resolves the content algorithm of a COSE_Mac or COSE_Encrypt
// body, where no key implies one: it must be in the protected bucket
// (so it is authenticated) and in allowed, which defaults to defaults.
// With the legacy policy, the protected alg is used as v0.2.2 did,
// ignoring an unprotected one.
func multiAlg(prot, unprot *Headers, p *headerPolicy, defaults []Algorithm) (Algorithm, error) {
	allowed := p.allowed
	if allowed == nil {
		allowed = defaults
	}
	var a Algorithm
	if p.legacyAlg {
		a = prot.Algorithm()
	} else {
		var loc algLocation
		var err error
		a, loc, err = headerAlg(prot, unprot)
		if err != nil {
			return 0, err
		}
		switch loc {
		case algAbsent:
			return 0, fmt.Errorf("%w: no alg header", ErrAlgorithmMismatch)
		case algUnprotected:
			return 0, fmt.Errorf("%w: alg must be in the protected bucket", ErrAlgorithmMismatch)
		}
	}
	if !slices.Contains(allowed, a) {
		return 0, fmt.Errorf("%w: %s not in allowed algorithms", ErrAlgorithmMismatch, a)
	}
	return a, nil
}

// checkCrit enforces RFC 9052 §3.1 for one layer: crit must be in the
// protected bucket and be a non-empty array of labels, and every listed
// label must be present in the protected bucket and be one this package
// interprets (the RFC 9052 labels 1-6) or one the caller declared with
// a KnownCriticalHeaders option.
func checkCrit(prot, unprot *Headers, p *headerPolicy) error {
	if p.legacyCrit {
		return nil
	}
	if _, ok := unprot.params[headerLabelCritical]; ok {
		return fmt.Errorf("%w: crit must be in the protected bucket", ErrCriticalHeader)
	}
	v, ok := prot.params[headerLabelCritical]
	if !ok {
		return nil
	}
	labels, err := critLabels(v)
	if err != nil {
		return err
	}
	for _, l := range labels {
		if _, present := prot.params[l]; !present {
			return fmt.Errorf("%w: crit label %v is not in the protected bucket", ErrCriticalHeader, l)
		}
		if !critUnderstood(l, p.knownCrit) {
			return fmt.Errorf("%w: crit label %v is not processed", ErrCriticalHeader, l)
		}
	}
	return nil
}

func critLabels(v any) ([]any, error) {
	var raw []any
	switch x := v.(type) {
	case corecbor.Value:
		if x.Kind != corecbor.KindArray {
			return nil, fmt.Errorf("%w: crit must be an array", ErrCriticalHeader)
		}
		for _, it := range x.Array() {
			l, err := labelToGo(it)
			if err != nil {
				return nil, fmt.Errorf("%w: crit: %w", ErrCriticalHeader, err)
			}
			raw = append(raw, l)
		}
	case []any:
		for _, it := range x {
			l, ok := normalizeLabel(it)
			if !ok {
				return nil, fmt.Errorf("%w: crit label %v is not int or tstr", ErrCriticalHeader, it)
			}
			raw = append(raw, l)
		}
	default:
		return nil, fmt.Errorf("%w: crit must be an array", ErrCriticalHeader)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: crit must not be empty", ErrCriticalHeader)
	}
	return raw, nil
}

func critUnderstood(l any, known []any) bool {
	if n, ok := l.(int64); ok && n >= 1 && n <= 6 {
		return true
	}
	return slices.Contains(known, l)
}

// defaultMACMultiAlgs are the header algorithms VerifyMACMulti accepts
// without WithMACAlgorithms. HMAC 256/64 is excluded: the header is
// attacker-controlled, and selecting it truncates the tag to 64 bits.
var defaultMACMultiAlgs = []Algorithm{AlgHMAC256, AlgHMAC384, AlgHMAC512}

// defaultEncryptMultiAlgs are the content algorithms DecryptMulti
// accepts without WithEncryptAlgorithms.
var defaultEncryptMultiAlgs = []Algorithm{AlgA128GCM, AlgA192GCM, AlgA256GCM}
