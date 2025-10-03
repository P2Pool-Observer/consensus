package crypto

import (
	"crypto/subtle"
	"encoding/binary"
	"math/big"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/edwards25519/field"
	"git.gammaspectra.live/P2Pool/sha3"
)

// l = 2^252 + 27742317777372353535851937790883648493.
var l = [32]byte{0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}

// limit = l * 15, l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
var limit = [32]byte{0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0}

func ScalarReduce32_BigInt(s *[32]byte) {
	// l = 2^252 + 27742317777372353535851937790883648493
	var lAdd, _ = new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	var l = new(big.Int).Add(new(big.Int).Exp(big.NewInt(2), big.NewInt(252), nil), lAdd)

	slices.Reverse(s[:])
	i := new(big.Int).SetBytes(s[:])
	i.Mod(i, l)
	i.FillBytes(s[:])
	slices.Reverse(s[:])
	return
}

// DecodeCompressedPoint Decompress a canonically-encoded Ed25519 point.
//
// Ed25519 is of order `8 * l`. This function ensures each of those `8 * l` points have a
// singular encoding by checking points aren't encoded with an unreduced field element,
// and aren't negative when the negative is equivalent (0 == -0).
//
// Since this decodes an Ed25519 point, it does not check the point is in the prime-order
// subgroup. Torsioned points do have a canonical encoding, and only aren't canonical when
// considered in relation to the prime-order subgroup.
func DecodeCompressedPoint(r *edwards25519.Point, buf [PublicKeySize]byte) *edwards25519.Point {
	if r == nil {
		return nil
	}
	p, err := r.SetBytes(buf[:])
	if err != nil {
		return nil
	}

	// Ban points which are either unreduced or -0
	if subtle.ConstantTimeCompare(p.Bytes(), buf[:]) == 0 {
		return nil
	}
	return p
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

func ScalarReduce32_Wide(s *[32]byte) {
	var x edwards25519.Scalar
	var data [64]byte
	copy(data[:], s[:])
	_, _ = x.SetUniformBytes(data[:])
	copy(s[:], x.Bytes())
}

// ScalarReduce32
// also called sc_reduce32
// 256-bit s integer modulo l
// equivalent to ScalarReduce32_BigInt
// equivalent to ScalarReduce32_Wide
//
//go:nosplit
func ScalarReduce32(s *[32]byte) {
	_ = s[31] // bounds check hint to compiler; see golang.org/issue/14808

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
	_, _ = c.SetUniformBytes(buf[:])
}

//go:nosplit
func BytesToScalar32(buf [32]byte, c *edwards25519.Scalar) {
	ScalarReduce32(&buf)
	_, _ = c.SetCanonicalBytes(buf[:])
}

func elementFromUint64(x uint64) *field.Element {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], x)

	e, err := new(field.Element).SetBytes(b[:])
	if err != nil {
		panic(err)
	}
	return e
}

var (
	_ONE          = new(field.Element).One()
	_NEGATIVE_ONE = new(field.Element).Negate(_ONE)
	_A            = elementFromUint64(486662)
	_NEGATIVE_A   = new(field.Element).Negate(_A)
)

// elligator2WithUniformBytes
// Equivalent to ge_fromfe_frombytes_vartime
// constant time
func elligator2WithUniformBytes(buf [32]byte) *edwards25519.Point {
	/*
	   Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

	   A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
	   `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
	*/

	// Convert the uniform bytes to a FieldElement
	/*
	   This isn't a wide reduction, implying it'd be biased, yet the bias should only be negligible
	   due to the shape of the prime number. All elements within the prime field field have a
	   `2 / 2^{256}` chance of being selected, except for the first 19 which have a `3 / 2^256`
	   chance of being selected. In order for this 'third chance' (the bias) to be relevant, the
	   hash function would have to output a number greater than or equal to:

	     0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda

	   which is of negligible probability.
	*/

	var r, o, tmp1, tmp2, tmp3 field.Element
	_, _ = r.SetBytesPropagate(buf[:])

	// Per Section 5.5, take `u = 2`. This is the smallest quadratic non-residue in the field
	urSquare := r.Square(&r)
	urSquareDouble := urSquare.Add(urSquare, urSquare)

	/*
	   We know this is non-zero as:

	   ```sage
	   p = 2**255 - 19
	   Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
	   ```
	*/
	onePlusUrSquare := urSquareDouble.Add(_ONE, urSquareDouble)
	onePlusUrSquareInverted := onePlusUrSquare.Invert(onePlusUrSquare)

	upsilon := onePlusUrSquareInverted.Multiply(_NEGATIVE_A, onePlusUrSquareInverted)

	/*
	   Quoting section 5.5,
	   "then \epsilon = 1 and x = \upsilon. Otherwise \epsilon = -1, x = \upsilon u r^2"

	   Whereas in the specification present in Section 5.2, the expansion of the `u` coordinate when
	   `\epsilon = -1` is `-\upsilon - A`. Per Section 5.2, in the "Second case",
	   `= -\upsilon - A = \upsilon u r^2`. These two values are equivalent, yet the negation and
	   subtract outperform a multiplication.
	*/
	otherCandidate := o.Subtract(tmp1.Negate(upsilon), _A)

	/*
	   Check if `\upsilon` is a valid `u` coordinate by checking for a solution for the square root
	   of `\upsilon^3 + A \upsilon^2 + \upsilon`.
	*/
	_, epsilon := tmp3.SqrtRatio(
		tmp3.Add(
			tmp3.Multiply(
				tmp1.Add(upsilon, _A),
				tmp2.Square(upsilon),
			),
			upsilon,
		),
		_ONE,
	)

	// select upsilon when epsilon is 1 (isSquare)
	u := r.Select(upsilon, otherCandidate, epsilon)

	// Map from Curve25519 to Ed25519
	/*
	   Elligator 2's specification in section 5.2 says to choose the negative square root as the
	   `v` coordinate if `\upsilon` was chosen (as signaled by `\epsilon = 1`). The following
	   chooses the odd `y` coordinate if `\upsilon` was chosen, which is functionally equivalent.
	*/
	return montgomeryToEdwards(u, epsilon)
}

// montgomeryToEdwards
// constant time
func montgomeryToEdwards(u *field.Element, sign int) *edwards25519.Point {
	if u == nil || u.Equal(_NEGATIVE_ONE) == 1 {
		return nil
	}

	var tmp1, tmp2 field.Element

	// The birational map is y = (u-1)/(u+1).
	y := u.Multiply(
		tmp1.Subtract(u, _ONE),
		tmp2.Invert(tmp2.Add(u, _ONE)),
	)

	var yBytes [32]byte
	copy(yBytes[:], y.Bytes())
	yBytes[31] ^= byte(sign << 7)

	return DecodeCompressedPoint(new(edwards25519.Point), yBytes)
}

func inlineKeccak[T ~[]byte | ~string](data T) []byte {
	_, _ = _hasher.Write([]byte(data))
	var h types.Hash
	HashFastSum(_hasher, h[:])
	_hasher.Reset()
	return h[:]
}

var (
	_hasher = sha3.NewLegacyKeccak256()

	// GeneratorG generator of 𝔾E
	// G = {x, 4/5 mod q}
	GeneratorG = edwards25519.NewGeneratorPoint()

	// GeneratorH H_p^1(G)
	// H = 8*to_point(keccak(G))
	// note: this does not use the point_from_bytes() function found in H_p(), instead directly interpreting the
	//       input bytes as a compressed point (this can fail, so should not be used generically)
	// note2: to_point(keccak(G)) is known to succeed for the canonical value of G (it will fail 7/8ths of the time
	//        normally)
	GeneratorH = HopefulHashToPoint(GeneratorG.Bytes())

	// GeneratorT H_p^2(Keccak256("Monero Generator T"))
	GeneratorT = UnbiasedHashToPoint(inlineKeccak("Monero Generator T"))

	// GeneratorU H_p^2(Keccak256("Monero FCMP++ Generator U"))
	GeneratorU = UnbiasedHashToPoint(inlineKeccak("Monero FCMP++ Generator U"))

	// GeneratorV H_p^2(Keccak256("Monero FCMP++ Generator V"))
	GeneratorV = UnbiasedHashToPoint(inlineKeccak("Monero FCMP++ Generator V"))
)
