// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import "strconv"

var kindNames = [...]string{
	KindInvalid:   "invalid",
	KindUint:      "uint",
	KindNegInt:    "negint",
	KindBytes:     "bytes",
	KindText:      "text",
	KindArray:     "array",
	KindMap:       "map",
	KindTag:       "tag",
	KindBool:      "bool",
	KindNull:      "null",
	KindUndefined: "undefined",
	KindFloat32:   "float32",
	KindFloat64:   "float64",
	KindSimple:    "simple",
}

// String returns the kind's name ("uint", "negint", "bytes", "text",
// "array", "map", "tag", "bool", "null", "undefined", "float32",
// "float64", "simple", or "invalid"); other values print as "Kind(N)".
// It implements fmt.Stringer, so %v and %s print names; %d still prints
// the number.
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "Kind(" + strconv.Itoa(int(k)) + ")"
}
