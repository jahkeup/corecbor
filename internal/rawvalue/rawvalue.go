// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package rawvalue carries pre-encoded CBOR through a Value tree so the
// encoder can splice it verbatim. It is internal: such Values only
// exist between reflection and encoding (proposal 022, Permissive-mode
// RawMessage/RawTag), never in a tree a caller can see.
package rawvalue

import "github.com/jahkeup/corecbor/cbor"

// Kind marks a Value whose Bstr holds one complete, already-validated
// encoded data item to be written as-is.
const Kind cbor.Kind = 0xff

// Make wraps encoded bytes as a raw Value.
func Make(encoded []byte) cbor.Value {
	return cbor.Value{Kind: Kind, Bstr: encoded}
}
