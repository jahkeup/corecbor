// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc_test

import (
	g "github.com/jahkeup/corecbor/internal/goldentest"

	"github.com/jahkeup/corecbor/edhoc"
)

// Sentinels added after v0.2.2. They live here, not in
// golden_v022_test.go, because tools/golden-regen.sh compiles that file
// against the v0.2.2 tag, where these identifiers don't exist. Appended
// last so errors that also match a v0.2.2 sentinel are still recorded
// under the old name.
func init() {
	edhocSentinels = append(
		edhocSentinels,
		g.Sentinel{Name: "ErrPeerError", Err: edhoc.ErrPeerError},
		g.Sentinel{Name: "ErrCredentialRejected", Err: edhoc.ErrCredentialRejected},
		g.Sentinel{Name: "ErrConnectionIDCollision", Err: edhoc.ErrConnectionIDCollision},
		g.Sentinel{Name: "ErrCriticalEAD", Err: edhoc.ErrCriticalEAD},
	)
}
