//go:build !tinygo

// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import "unsafe"

func zeroCopyString(src []byte, start, end int) string {
	// SliceData, not &src[start]: an empty string may start at
	// len(src), where indexing would panic.
	return unsafe.String(unsafe.SliceData(src[start:end]), end-start)
}
