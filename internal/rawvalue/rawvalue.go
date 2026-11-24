// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

// Package rawvalue carries pre-encoded CBOR through a Value tree so the
// encoder can splice it verbatim. It is internal: such Values only
// exist between reflection and encoding (Permissive-mode RawMessage and
// RawTag), never in a tree a caller can see.
package rawvalue

import "github.com/jahkeup/corecbor/cbor"

// Kind marks a Value whose Bstr holds one complete, already-validated
// encoded data item to be written as-is.
const Kind cbor.Kind = 0xff

// marker identifies Values made by Make. Its address can't be obtained
// outside this module, so a caller who builds a Value with Kind by hand
// gets the encoder's ordinary "unsupported kind" error instead of having
// arbitrary bytes spliced into the output.
var marker [1]cbor.Value

// Make wraps encoded bytes as a raw Value.
func Make(encoded []byte) cbor.Value {
	return cbor.Value{Kind: Kind, Bstr: encoded, Items: marker[:]}
}

// Is reports whether v was produced by Make.
func Is(v *cbor.Value) bool {
	return v.Kind == Kind && len(v.Items) == 1 && &v.Items[0] == &marker[0]
}
