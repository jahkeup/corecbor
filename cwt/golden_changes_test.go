// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

// goldenChanges lists golden vector IDs whose results may differ from
// v0.2.2, keyed to the proposal that changes them. Per proposal 034 only
// safety and contract defect fixes may change existing behavior. Add an
// entry in the same change that alters the behavior.
var goldenChanges = map[string]string{
	"cwt/validate/negative-leeway": "proposal 021 D17: negative Leeway returns ErrInvalidValidator instead of tightening the window",
}
