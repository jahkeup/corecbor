// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

//go:build race

package corecbor

// raceEnabled reports a -race build. The race detector makes sync.Pool
// drop items at random, so pooled paths allocate and allocation-count
// tests don't hold.
const raceEnabled = true
