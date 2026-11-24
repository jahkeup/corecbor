// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import "github.com/jahkeup/corecbor/cbor"

// RFC 8746 typed arrays (proposal 037 C18). See package cbor for the
// documentation of each.

// TypedArrayElem lists the Go element types of the supported typed
// arrays.
type TypedArrayElem = cbor.TypedArrayElem

// TagUint8ClampedArray is the RFC 8746 tag for a clamped uint8 array.
const TagUint8ClampedArray = cbor.TagUint8ClampedArray

// TypedArrayTo returns s as a big-endian RFC 8746 typed array.
func TypedArrayTo[T TypedArrayElem](s []T) Value { return cbor.TypedArrayTo(s) }

// TypedArrayToLE returns s as a little-endian RFC 8746 typed array.
func TypedArrayToLE[T TypedArrayElem](s []T) Value { return cbor.TypedArrayToLE(s) }

// AsTypedArray returns the elements of an RFC 8746 typed array of T.
func AsTypedArray[T TypedArrayElem](t Value) ([]T, error) { return cbor.AsTypedArray[T](t) }

// Tags for RFC 8746 multi-dimensional and homogeneous arrays.
const (
	TagMultiDimArray            = cbor.TagMultiDimArray
	TagHomogeneousArray         = cbor.TagHomogeneousArray
	TagMultiDimArrayColumnMajor = cbor.TagMultiDimArrayColumnMajor
)

// MultiDimArray is an RFC 8746 multi-dimensional array.
type MultiDimArray = cbor.MultiDimArray

var (
	AsFloat64Array     = cbor.AsFloat64Array
	AsFloat128Array    = cbor.AsFloat128Array
	MultiDimArrayTo    = cbor.MultiDimArrayTo
	AsMultiDimArray    = cbor.AsMultiDimArray
	HomogeneousArrayTo = cbor.HomogeneousArrayTo
	AsHomogeneousArray = cbor.AsHomogeneousArray
)
