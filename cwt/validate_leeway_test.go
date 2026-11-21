// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt

import (
	"errors"
	"testing"
	"time"
)

func TestValidateNegativeLeeway(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	claims := &ClaimsSet{Expiration: now.Add(time.Minute)}
	v := &Validator{Leeway: -time.Hour, Now: func() time.Time { return now }}
	if err := v.Validate(claims); !errors.Is(err, ErrInvalidValidator) {
		t.Fatalf("err = %v, want ErrInvalidValidator", err)
	}
	v.Leeway = 0
	if err := v.Validate(claims); err != nil {
		t.Fatalf("zero leeway: %v", err)
	}
}
