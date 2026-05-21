package eat

import (
	"bytes"

	"github.com/jahkeup/corecbor/cwt"
)

// Appraiser evaluates EAT claims against a set of policy requirements.
type Appraiser struct {
	RequireNonce         []byte
	RequireSecurityLevel SecurityLevel
	RequireSecureBoot    bool
	RequireDebugDisabled bool
	RequireProfile       string
	SWComponentPolicy    func([]SWComponent) error
	CWTValidator         *cwt.Validator
	Custom               []func(*Claims) error
}

// Appraise checks the claims against all configured policy requirements.
func (a *Appraiser) Appraise(claims *Claims) error {
	if len(a.RequireNonce) > 0 {
		if !nonceMatches(claims.Nonce, a.RequireNonce) {
			return ErrNonceMismatch
		}
	}

	if a.RequireSecurityLevel > 0 {
		if claims.SecurityLevel < a.RequireSecurityLevel {
			return ErrSecurityLevel
		}
	}

	if a.RequireSecureBoot {
		if claims.SecureBoot == nil || !*claims.SecureBoot {
			return ErrSecureBootRequired
		}
	}

	if a.RequireDebugDisabled {
		if claims.Debug == DebugEnabled {
			return ErrDebugEnabled
		}
	}

	if a.RequireProfile != "" {
		if claims.Profile != a.RequireProfile {
			return ErrProfileMismatch
		}
	}

	if a.SWComponentPolicy != nil && len(claims.SWComponents) > 0 {
		if err := a.SWComponentPolicy(claims.SWComponents); err != nil {
			return err
		}
	}

	if a.CWTValidator != nil {
		if err := a.CWTValidator.Validate(&claims.ClaimsSet); err != nil {
			return err
		}
	}

	for _, fn := range a.Custom {
		if err := fn(claims); err != nil {
			return err
		}
	}

	return nil
}

func nonceMatches(nonces [][]byte, expected []byte) bool {
	for _, n := range nonces {
		if bytes.Equal(n, expected) {
			return true
		}
	}
	return false
}
