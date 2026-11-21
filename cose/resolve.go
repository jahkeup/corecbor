// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"errors"
	"fmt"
)

// KeyResolver selects candidate verification keys for a message layer
// from its headers. It returns COSE_Keys, so each key's alg and key_ops
// are applied when verifying. Implementations MUST treat the unprotected
// bucket as an untrusted hint (for example a kid used only to narrow the
// search): every candidate is still checked cryptographically, and alg
// is bound to the key.
type KeyResolver interface {
	ResolveKey(ctx context.Context, protected, unprotected *Headers) ([]*Key, error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(ctx context.Context, protected, unprotected *Headers) ([]*Key, error)

// ResolveKey calls f.
func (f KeyResolverFunc) ResolveKey(ctx context.Context, protected, unprotected *Headers) ([]*Key, error) {
	return f(ctx, protected, unprotected)
}

// KeySetResolver resolves keys from ks by the layer's kid (protected or
// unprotected) and alg, among keys whose key_ops permit verify. A layer
// without a kid gets every matching key.
func KeySetResolver(ks KeySet) KeyResolver {
	return KeyResolverFunc(func(_ context.Context, prot, unprot *Headers) ([]*Key, error) {
		var kid []byte
		if v, ok := Lookup(prot, unprot, headerLabelKeyID); ok {
			kid, _ = v.([]byte)
		}
		var alg Algorithm
		if v, ok := Lookup(prot, unprot, headerLabelAlgorithm); ok {
			alg, _ = algValue(v)
		}
		return ks.Lookup(kid, alg, KeyOpVerify), nil
	})
}

// VerifySign1 verifies msg with the keys r resolves, under the same
// policy as Verifier.Verify (opts apply to every candidate). The first
// key that verifies wins. It returns ErrVerification if r yields no key
// or none verifies, wrapping the last policy error when there is one;
// resolver errors and ctx cancellation are returned as is.
func VerifySign1(ctx context.Context, msg *Sign1, r KeyResolver, opts ...VerifierOption) error {
	if msg.Payload == nil {
		return ErrMissingPayload
	}
	return verifySign1Resolved(ctx, msg, msg.Payload, r, opts)
}

// VerifySign1Detached is VerifySign1 for a detached payload.
func VerifySign1Detached(ctx context.Context, msg *Sign1, payload []byte, r KeyResolver, opts ...VerifierOption) error {
	return verifySign1Resolved(ctx, msg, payload, r, opts)
}

func verifySign1Resolved(ctx context.Context, msg *Sign1, payload []byte, r KeyResolver, opts []VerifierOption) error {
	keys, err := r.ResolveKey(ctx, &msg.Protected, &msg.Unprotected)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no key resolved", ErrVerification)
	}
	var lastErr error
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		v, err := NewVerifierFromKey(k, opts...)
		if err != nil {
			lastErr = err
			continue
		}
		err = v.VerifyDetached(msg, payload)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if lastErr != nil && !errors.Is(lastErr, ErrVerification) {
		return fmt.Errorf("%w: no resolved key verified: %w", ErrVerification, lastErr)
	}
	return fmt.Errorf("%w: no resolved key verified", ErrVerification)
}
