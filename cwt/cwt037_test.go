// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cwt"
)

// Proposal 037 tests.

// claimKeyOf returns the claim a *cwt.ClaimError names, or false.
func claimKeyOf(err error) (cwt.ClaimKey, bool) {
	var ce *cwt.ClaimError
	if !errors.As(err, &ce) {
		return cwt.ClaimKey{}, false
	}
	return ce.Key, true
}

// W1: RFC 7519 §4.1.3 — a token whose aud the processor doesn't
// identify with is rejected, whether or not an audience is configured.
func TestValidator_Audience037(t *testing.T) {
	aud := func(a ...string) *cwt.ClaimsSet { return &cwt.ClaimsSet{Audiences: a} }
	for _, tc := range []struct {
		name   string
		v      cwt.Validator
		claims *cwt.ClaimsSet
		want   error
	}{
		{"no aud, none configured", cwt.Validator{}, &cwt.ClaimsSet{}, nil},
		{"aud, none configured", cwt.Validator{}, aud("rs1"), cwt.ErrAudienceMismatch},
		{"single-string aud, none configured", cwt.Validator{}, &cwt.ClaimsSet{Audience: "rs1"}, cwt.ErrAudienceMismatch},
		{"empty-string aud, none configured", cwt.Validator{}, aud(""), cwt.ErrAudienceMismatch},
		{"aud matches Audience", cwt.Validator{Audience: "rs1"}, aud("rs0", "rs1"), nil},
		{"aud matches one of Audiences", cwt.Validator{Audiences: []string{"x", "rs1"}}, aud("rs1"), nil},
		{"aud matches none of Audiences", cwt.Validator{Audiences: []string{"x", "y"}}, aud("rs1"), cwt.ErrAudienceMismatch},
		{"Audiences configured, no aud", cwt.Validator{Audiences: []string{"x"}}, &cwt.ClaimsSet{}, cwt.ErrAudienceMismatch},
		{"IgnoreAudience", cwt.Validator{IgnoreAudience: true}, aud("rs1"), nil},
		{"IgnoreAudience with Audience", cwt.Validator{IgnoreAudience: true, Audience: "rs1"}, aud("rs1"), cwt.ErrInvalidValidator},
		{"IgnoreAudience with Audiences", cwt.Validator{IgnoreAudience: true, Audiences: []string{"rs1"}}, aud("rs1"), cwt.ErrInvalidValidator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.v.Validate(tc.claims)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
			if tc.want == cwt.ErrAudienceMismatch {
				if k, ok := claimKeyOf(err); !ok || k != cwt.IntKey(cwt.ClaimAud) {
					t.Fatalf("error %v does not name the aud claim", err)
				}
			}
		})
	}

	// NewValidator applies the same rule.
	v := cwt.NewValidator()
	v.Now = func() time.Time { return t0 }
	c := validClaims()
	c.Audience = "rs1"
	if err := v.Validate(c); !errors.Is(err, cwt.ErrAudienceMismatch) {
		t.Fatalf("NewValidator, unexpected aud: %v", err)
	}
	v.Audiences = []string{"rs1"}
	if err := v.Validate(c); err != nil {
		t.Fatalf("NewValidator, expected aud: %v", err)
	}
}
