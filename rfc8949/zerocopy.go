//go:build !tinygo

// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package rfc8949

import "unsafe"

func zeroCopyString(src []byte, start, end int) string {
	return unsafe.String(&src[start], end-start)
}
