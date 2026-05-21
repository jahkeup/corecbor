package wire

import (
	"encoding/binary"
	"math"
)

// DecodeFloat16 converts a 16-bit IEEE 754 half-precision float (stored
// as uint16 in network byte order) to a float64.
//
// This implements RFC 8949 Appendix D.
func DecodeFloat16(bits uint16) float64 {
	exp := int((bits >> 10) & 0x1f)
	mant := bits & 0x3ff
	var val float64
	switch exp {
	case 0:
		// Subnormal or zero.
		val = math.Ldexp(float64(mant), -24)
	case 31:
		// Infinity or NaN.
		if mant == 0 {
			val = math.Inf(1)
		} else {
			val = math.NaN()
		}
	default:
		val = math.Ldexp(float64(mant)+1024, exp-25)
	}
	if bits&0x8000 != 0 {
		val = -val
	}
	return val
}

// EncodeFloat16 attempts to encode f as a 16-bit half-precision float.
// Returns the encoded bits and true if the conversion is lossless,
// or 0 and false if f cannot be represented in float16 without
// precision loss.
func EncodeFloat16(f float64) (uint16, bool) {
	if math.IsNaN(f) {
		// Canonical NaN: 0x7e00 (positive, quiet, no payload).
		return 0x7e00, true
	}

	var sign uint16
	if math.Signbit(f) {
		sign = 0x8000
		f = -f
	}

	if math.IsInf(f, 1) {
		return sign | 0x7c00, true
	}

	if f == 0 {
		return sign, true
	}

	// float16: 1 sign + 5 exponent (bias 15) + 10 mantissa
	// Convert via float32 intermediate, check for precision loss.
	f32 := float32(f)
	if float64(f32) != f {
		return 0, false
	}
	f32bits := math.Float32bits(f32)
	f32exp := int((f32bits>>23)&0xff) - 127
	f32mant := f32bits & 0x7fffff

	var bits uint16
	switch {
	case f32exp < -24:
		return 0, false
	case f32exp < -14:
		// Subnormal float16: shift mantissa right.
		shift := uint(-14 - f32exp)
		mant := (f32mant | 0x800000) >> (13 + shift)
		// Check dropped bits are zero.
		if mant<<(13+shift) != (f32mant | 0x800000) {
			return 0, false
		}
		bits = sign | uint16(mant)
	case f32exp <= 15:
		// Normal float16.
		if f32mant&0x1fff != 0 {
			return 0, false
		}
		exp16 := uint16(f32exp+15) & 0x1f
		mant16 := uint16(f32mant >> 13)
		bits = sign | (exp16 << 10) | mant16
	default:
		return 0, false
	}

	// Round-trip: decode must reproduce the absolute value.
	if DecodeFloat16(bits&0x7fff) != f {
		return 0, false
	}
	return bits, true
}

// NOTE: Phase 4 optimization target — EncodeFloat16 does a float32
// intermediate + round-trip check. A direct bit-manipulation path
// avoiding the float32 intermediate would eliminate the float32
// conversion and comparison. Profile before optimizing.

// CanFloat32Lossless reports whether f can be represented exactly as
// a float32.
func CanFloat32Lossless(f float64) bool {
	if math.IsNaN(f) {
		return true // NaN is representable in both widths
	}
	return float64(float32(f)) == f
}

// AppendFloat16 appends a CBOR float16 (marker + 2 bytes) to dst.
func AppendFloat16(dst []byte, bits uint16) []byte {
	return binary.BigEndian.AppendUint16(append(dst, Float16Marker), bits)
}

// AppendFloat32 appends a CBOR float32 (marker + 4 bytes) to dst.
func AppendFloat32(dst []byte, f float32) []byte {
	return binary.BigEndian.AppendUint32(append(dst, Float32Marker), math.Float32bits(f))
}

// AppendFloat64 appends a CBOR float64 (marker + 8 bytes) to dst.
func AppendFloat64(dst []byte, f float64) []byte {
	return binary.BigEndian.AppendUint64(append(dst, Float64Marker), math.Float64bits(f))
}
