package wire

import (
	"math"
	"testing"
)

func TestAppendHead(t *testing.T) {
	tests := []struct {
		major byte
		arg   uint64
		want  []byte
	}{
		{MajorUint, 0, []byte{0x00}},
		{MajorUint, 23, []byte{0x17}},
		{MajorUint, 24, []byte{0x18, 0x18}},
		{MajorUint, 255, []byte{0x18, 0xff}},
		{MajorUint, 256, []byte{0x19, 0x01, 0x00}},
		{MajorUint, 65535, []byte{0x19, 0xff, 0xff}},
		{MajorUint, 65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
		{MajorUint, 0xffffffff, []byte{0x1a, 0xff, 0xff, 0xff, 0xff}},
		{MajorUint, 0x100000000, []byte{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
		{MajorNegInt, 0, []byte{0x20}},
		{MajorNegInt, 9, []byte{0x29}},
		{MajorBytes, 5, []byte{0x45}},
		{MajorText, 4, []byte{0x64}},
		{MajorArray, 3, []byte{0x83}},
		{MajorMap, 2, []byte{0xa2}},
		{MajorTag, 1, []byte{0xc1}},
	}
	for _, tt := range tests {
		got := AppendHead(nil, tt.major, tt.arg)
		if len(got) != len(tt.want) {
			t.Errorf("AppendHead(%#x, %d): got %x, want %x", tt.major, tt.arg, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("AppendHead(%#x, %d): got %x, want %x", tt.major, tt.arg, got, tt.want)
				break
			}
		}
	}
}

func TestParseHead(t *testing.T) {
	tests := []struct {
		src   []byte
		major byte
		ai    byte
		arg   uint64
		n     int
	}{
		{[]byte{0x00}, MajorUint, 0, 0, 1},
		{[]byte{0x17}, MajorUint, 23, 23, 1},
		{[]byte{0x18, 0x18}, MajorUint, AI1Byte, 24, 2},
		{[]byte{0x19, 0x01, 0x00}, MajorUint, AI2Bytes, 256, 3},
		{[]byte{0x1a, 0x00, 0x01, 0x00, 0x00}, MajorUint, AI4Bytes, 65536, 5},
		{[]byte{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, MajorUint, AI8Bytes, 0x100000000, 9},
		{[]byte{0x20}, MajorNegInt, 0, 0, 1},
		{[]byte{0x38, 0x63}, MajorNegInt, AI1Byte, 99, 2},
		{[]byte{}, 0, 0, 0, 0},     // empty input
		{[]byte{0x18}, 0, 0, 0, 0}, // truncated
	}
	for _, tt := range tests {
		h := ParseHead(tt.src)
		if h.N != tt.n {
			t.Errorf("ParseHead(%x): N=%d, want %d", tt.src, h.N, tt.n)
			continue
		}
		if h.N == 0 {
			continue
		}
		if h.Major != tt.major || h.AI != tt.ai || h.Arg != tt.arg {
			t.Errorf("ParseHead(%x): got {%#x, %d, %d}, want {%#x, %d, %d}",
				tt.src, h.Major, h.AI, h.Arg, tt.major, tt.ai, tt.arg)
		}
	}
}

func TestParseHeadRoundTrip(t *testing.T) {
	majors := []byte{MajorUint, MajorNegInt, MajorBytes, MajorText, MajorArray, MajorMap, MajorTag}
	args := []uint64{0, 1, 23, 24, 255, 256, 65535, 65536, 0xffffffff, 0x100000000, 0xffffffffffffffff}

	for _, major := range majors {
		for _, arg := range args {
			encoded := AppendHead(nil, major, arg)
			h := ParseHead(encoded)
			if h.N == 0 {
				t.Fatalf("ParseHead returned N=0 for AppendHead(%#x, %d) = %x", major, arg, encoded)
			}
			if h.Major != major || h.Arg != arg {
				t.Errorf("round-trip failed: major=%#x arg=%d → encoded=%x → parsed={%#x, %d}",
					major, arg, encoded, h.Major, h.Arg)
			}
			if !h.IsShortest() {
				t.Errorf("AppendHead produced non-shortest encoding for arg=%d", arg)
			}
		}
	}
}

func TestDecodeFloat16(t *testing.T) {
	tests := []struct {
		bits uint16
		want float64
	}{
		{0x0000, 0.0},
		{0x8000, math.Copysign(0, -1)}, // -0.0
		{0x3c00, 1.0},
		{0x3e00, 1.5},
		{0x7bff, 65504.0},
		{0x0001, 5.960464477539063e-8}, // smallest subnormal
		{0x0400, 6.103515625e-5},       // smallest normal
		{0xc400, -4.0},
		{0x7c00, math.Inf(1)},
		{0xfc00, math.Inf(-1)},
		{0x7e00, math.NaN()},
	}
	for _, tt := range tests {
		got := DecodeFloat16(tt.bits)
		if math.IsNaN(tt.want) {
			if !math.IsNaN(got) {
				t.Errorf("DecodeFloat16(0x%04x) = %v, want NaN", tt.bits, got)
			}
		} else if got != tt.want {
			t.Errorf("DecodeFloat16(0x%04x) = %v, want %v", tt.bits, got, tt.want)
		}
	}
}

func TestEncodeFloat16RoundTrip(t *testing.T) {
	lossless := []float64{0.0, math.Copysign(0, -1), 1.0, 1.5, -4.0, 65504.0, math.Inf(1), math.Inf(-1), math.NaN()}
	for _, f := range lossless {
		bits, ok := EncodeFloat16(f)
		if !ok {
			t.Errorf("EncodeFloat16(%v) returned not-ok", f)
			continue
		}
		rt := DecodeFloat16(bits)
		if math.IsNaN(f) {
			if !math.IsNaN(rt) {
				t.Errorf("EncodeFloat16(%v) round-trip: got %v", f, rt)
			}
		} else if rt != f {
			t.Errorf("EncodeFloat16(%v) = 0x%04x, decodes to %v", f, bits, rt)
		}
	}

	lossy := []float64{1.1, 100000.0, 1e300, 1.0000001}
	for _, f := range lossy {
		_, ok := EncodeFloat16(f)
		if ok {
			t.Errorf("EncodeFloat16(%v) should be lossy but returned ok", f)
		}
	}
}
