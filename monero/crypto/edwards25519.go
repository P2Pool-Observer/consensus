package crypto

import (
	"encoding/binary"
	"math/big"
	"slices"

	"git.gammaspectra.live/P2Pool/edwards25519"
)

// l = 2^252 + 27742317777372353535851937790883648493.
var l = [32]byte{0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}

// limit = l * 15, l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
var limit = [32]byte{0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0}

func ScalarReduce32_BigInt(s []byte) {
	// l = 2^252 + 27742317777372353535851937790883648493
	var lAdd, _ = new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	var l = new(big.Int).Add(new(big.Int).Exp(big.NewInt(2), big.NewInt(252), nil), lAdd)

	slices.Reverse(s)
	i := new(big.Int).SetBytes(s)
	i.Mod(i, l)
	i.FillBytes(s)
	slices.Reverse(s)
	return
}

//go:nosplit
func IsLimit32(a [32]byte) bool {
	for n := 31; n >= 0; n-- {
		if a[n] < limit[n] {
			return true
		} else if a[n] > limit[n] {
			return false
		}
	}

	return false
}
func IsReduced32(a [32]byte) bool {
	for n := 31; n >= 0; n-- {
		if a[n] < l[n] {
			return true
		} else if a[n] > l[n] {
			return false
		}
	}

	return false
}

//go:nosplit
func load3(in []byte) (result int64) {
	_ = in[2] // bounds check hint to compiler; see golang.org/issue/14808
	result = int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16)
	return
}

//go:nosplit
func load4(in []byte) (result int64) {
	return int64(binary.LittleEndian.Uint32(in))
}

// ScalarReduce32
// also called sc_reduce32
// 256-bit s integer modulo l
// equivalent to ScalarReduce32_BigInt
//
//go:nosplit
func ScalarReduce32(s []byte) {
	_ = s[31] // bounds check hint to compiler; see golang.org/issue/14808

	var x edwards25519.Scalar
	var data [64]byte
	copy(data[:], s)
	_, _ = x.SetUniformBytes(data[:])
	copy(s, x.Bytes())

	s0 := 0x1FFFFF & load3(s[:])
	s1 := 0x1FFFFF & (load4(s[2:]) >> 5)
	s2 := 0x1FFFFF & (load3(s[5:]) >> 2)
	s3 := 0x1FFFFF & (load4(s[7:]) >> 7)
	s4 := 0x1FFFFF & (load4(s[10:]) >> 4)
	s5 := 0x1FFFFF & (load3(s[13:]) >> 1)
	s6 := 0x1FFFFF & (load4(s[15:]) >> 6)
	s7 := 0x1FFFFF & (load3(s[18:]) >> 3)
	s8 := 0x1FFFFF & load3(s[21:])
	s9 := 0x1FFFFF & (load4(s[23:]) >> 5)
	s10 := 0x1FFFFF & (load3(s[26:]) >> 2)
	s11 := load4(s[28:]) >> 7
	s12 := int64(0)
	var carry [12]int64
	carry[0] = (s0 + (1 << 20)) >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[2] = (s2 + (1 << 20)) >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[4] = (s4 + (1 << 20)) >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[1] = (s1 + (1 << 20)) >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[3] = (s3 + (1 << 20)) >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[5] = (s5 + (1 << 20)) >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	carry[11] = s11 >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901

	// same as above
	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	s[0] = byte(s0 >> 0)
	s[1] = byte(s0 >> 8)
	s[2] = byte((s0 >> 16) | (s1 << 5))
	s[3] = byte(s1 >> 3)
	s[4] = byte(s1 >> 11)
	s[5] = byte((s1 >> 19) | (s2 << 2))
	s[6] = byte(s2 >> 6)
	s[7] = byte((s2 >> 14) | (s3 << 7))
	s[8] = byte(s3 >> 1)
	s[9] = byte(s3 >> 9)
	s[10] = byte((s3 >> 17) | (s4 << 4))
	s[11] = byte(s4 >> 4)
	s[12] = byte(s4 >> 12)
	s[13] = byte((s4 >> 20) | (s5 << 1))
	s[14] = byte(s5 >> 7)
	s[15] = byte((s5 >> 15) | (s6 << 6))
	s[16] = byte(s6 >> 2)
	s[17] = byte(s6 >> 10)
	s[18] = byte((s6 >> 18) | (s7 << 3))
	s[19] = byte(s7 >> 5)
	s[20] = byte(s7 >> 13)
	s[21] = byte(s8 >> 0)
	s[22] = byte(s8 >> 8)
	s[23] = byte((s8 >> 16) | (s9 << 5))
	s[24] = byte(s9 >> 3)
	s[25] = byte(s9 >> 11)
	s[26] = byte((s9 >> 19) | (s10 << 2))
	s[27] = byte(s10 >> 6)
	s[28] = byte((s10 >> 14) | (s11 << 7))
	s[29] = byte(s11 >> 1)
	s[30] = byte(s11 >> 9)
	s[31] = byte(s11 >> 17)
}

//go:nosplit
func BytesToScalar64(buf [64]byte, c *edwards25519.Scalar) {
	_, _ = GetEdwards25519Scalar().SetUniformBytes(buf[:])
}

//go:nosplit
func BytesToScalar32(buf [32]byte, c *edwards25519.Scalar) {
	ScalarReduce32(buf[:])
	_, _ = c.SetCanonicalBytes(buf[:])
}
