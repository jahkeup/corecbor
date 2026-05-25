//go:build tinygo

// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

func zeroCopyString(src []byte, start, end int) string {
	return string(src[start:end])
}
