package curve25519

import (
	"encoding/binary"
	"math/bits"

	"git.gammaspectra.live/P2Pool/edwards25519" //nolint:depguard
)

// A Scalar is an integer modulo
//
//	l = 2^252 + 27742317777372353535851937790883648493
//
// which is the prime order of the edwards25519 group.
//
// This type works similarly to math/big.Int, and all arguments and
// receivers are allowed to alias.
//
// The zero value is a valid zero element.
//
// Mostly a passthrough implementation of edwards25519/Scalar
// Makes it compatible with the Field interface
// Added: Square, IsNegative, Negate
type Scalar edwards25519.Scalar

var scalarZero = (*Scalar)(new(edwards25519.Scalar).Zero())

var scalarOne = (*Scalar)(new(edwards25519.Scalar).One())

func (v *Scalar) S() *edwards25519.Scalar {
	return (*edwards25519.Scalar)(v)
}

func (v *Scalar) Zero() *Scalar {
	*v = *scalarZero
	return v
}

func (v *Scalar) One() *Scalar {
	*v = *scalarOne
	return v
}

func (v *Scalar) Add(a, b *Scalar) *Scalar {
	return (*Scalar)(v.S().Add(a.S(), b.S()))
}

func (v *Scalar) Subtract(a, b *Scalar) *Scalar {
	return (*Scalar)(v.S().Subtract(a.S(), b.S()))
}

func (v *Scalar) Multiply(a, b *Scalar) *Scalar {
	return (*Scalar)(v.S().Multiply(a.S(), b.S()))
}

func (v *Scalar) MultiplyAdd(x, y, z *Scalar) *Scalar {
	return (*Scalar)(v.S().MultiplyAdd(x.S(), y.S(), z.S()))
}

func (v *Scalar) Negate(x *Scalar) *Scalar {
	return (*Scalar)(v.S().Negate(x.S()))
}

func (v *Scalar) Invert(x *Scalar) *Scalar {
	return (*Scalar)(v.S().Invert(x.S()))
}

func (v *Scalar) Set(x *Scalar) *Scalar {
	return (*Scalar)(v.S().Set(x.S()))
}

func (v *Scalar) Square(x *Scalar) *Scalar {
	return (*Scalar)(v.S().Multiply(x.S(), x.S()))
}

func (v *Scalar) Absolute(x *Scalar) *Scalar {
	return v.Select(new(Scalar).Negate(x), x, x.IsNegative())
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *Scalar) IsNegative() int {
	return int(v.Bytes()[0] & 1)
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *Scalar) Equal(u *Scalar) int {
	return v.S().Equal(u.S())
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Scalar) Select(a, b *Scalar, cond int) *Scalar {
	return (*Scalar)(v.S().Select(a.S(), b.S(), cond))
}

// IsZero returns 1 if v is Zero, and 0 otherwise.
func (v *Scalar) IsZero() int {
	return v.Equal(scalarZero)
}

func (v *Scalar) Bytes() []byte {
	return v.S().Bytes()
}

// SetBytes sets s = x, where x is a 32-byte little-endian encoding of
// s, and returns s. If x is not a canonical encoding of s, SetBytes
// returns nil and an error, and the receiver is unchanged.
func (v *Scalar) SetBytes(x []byte) (*Scalar, error) {
	ret, err := v.S().SetCanonicalBytes(x)
	return (*Scalar)(ret), err
}

func (v *Scalar) SetWideBytes(x []byte) (*Scalar, error) {
	ret, err := v.S().SetUniformBytes(x)
	if err != nil {
		return nil, err
	}
	return (*Scalar)(ret), nil
}

// order is the order of the Ristretto group and of the Ed25519 basepoint, i.e., l = 2^252 + 27742317777372353535851937790883648493.
var order = [PrivateKeySize]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}
var orderLimbs = scalarLimbs(order)

const (
	orderLimb0 = 0x5812631a5cf5d3ed
	orderLimb1 = 0x14def9dea2f79cd6

	orderLimb2 = 0x0000000000000000
	orderLimb3 = 0x1000000000000000
)

// limit = order * 15, order fits 15 times in 32 bytes (iow, 15 order is the highest multiple of order that fits in 32 bytes)
var limit = [PrivateKeySize]byte{
	0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29,
	0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
}

var limitLimbs = scalarLimbs(limit)

func scalarLimbs[T ~[PrivateKeySize]byte](a T) (out [4]uint64) {
	return [4]uint64{
		binary.LittleEndian.Uint64(a[:]),
		binary.LittleEndian.Uint64(a[8:]),
		binary.LittleEndian.Uint64(a[16:]),
		binary.LittleEndian.Uint64(a[24:]),
	}
}

// scalarLess used to check that a < b
//
// Constant time
//
//go:nosplit
func scalarLess[T ~[PrivateKeySize]byte](a T, b *[4]uint64) bool {
	_, borrow := bits.Sub64(binary.LittleEndian.Uint64(a[:]), b[0], 0)
	_, borrow = bits.Sub64(binary.LittleEndian.Uint64(a[8:]), b[1], borrow)
	_, borrow = bits.Sub64(binary.LittleEndian.Uint64(a[16:]), b[2], borrow)
	_, borrow = bits.Sub64(binary.LittleEndian.Uint64(a[24:]), b[3], borrow)
	return borrow == 1
}

// scalarLessVarTime used to check that a < b
// Execution time depends on scalar value
//
// Variable time
//
//go:nosplit
func scalarLessVarTime[T1 ~[PrivateKeySize]byte, T2 ~[PrivateKeySize]byte](a T1, b T2) bool {
	for n := 31; n >= 0; n-- {
		if a[n] < b[n] {
			return true
		} else if a[n] > b[n] {
			return false
		}
	}
	return false
}

// ScalarIsLimit32 Checks if s is reduced mod limit
//
// Constant time
//
//go:nosplit
func ScalarIsLimit32[T ~[PrivateKeySize]byte](a T) bool {
	return scalarLess[T](a, &limitLimbs)
}

// ScalarIsReduced32 Checks if s is reduced mod order
//
// Constant time
//
//go:nosplit
func ScalarIsReduced32[T ~[PrivateKeySize]byte](a T) bool {
	return scalarLess[T](a, &orderLimbs)
}

// ScalarIsLimit32VarTime Checks if s is reduced mod limit
// Execution time depends on scalar value
//
// Variable time
//
//go:nosplit
func ScalarIsLimit32VarTime[T ~[PrivateKeySize]byte](a T) bool {
	return scalarLessVarTime[T](a, limit)
}

// ScalarIsReduced32VarTime Checks if s is reduced mod order
// Execution time depends on scalar value
//
// Variable time
//
//go:nosplit
func ScalarIsReduced32VarTime[T ~[PrivateKeySize]byte](a T) bool {
	return scalarLessVarTime[T](a, order)
}

// ScalarReduce32 256-bit little endian integer mod order
// also called sc_reduce32 in Monero
//
// Constant time
//
//go:nosplit
func ScalarReduce32[T ~[PrivateKeySize]byte](s *T) {
	// 64-bit limbs
	s0 := binary.LittleEndian.Uint64((*s)[:])
	s1 := binary.LittleEndian.Uint64((*s)[8:])
	s2 := binary.LittleEndian.Uint64((*s)[16:])
	s3 := binary.LittleEndian.Uint64((*s)[24:])

	// q = floor(s / 2^252)
	q := s3 >> 60
	// keep s mod 2^252
	s3 &= (1 << 60) - 1

	// q*d, at most 129 bits wide, check using delta part of order
	hi0, d0 := bits.Mul64(q, orderLimb0)
	hi1, lo1 := bits.Mul64(q, orderLimb1)
	d1, carry := bits.Add64(hi0, lo1, 0)
	d2 := hi1 + carry

	// s -= q*d, carry borrow
	s0, borrow := bits.Sub64(s0, d0, 0)
	s1, borrow = bits.Sub64(s1, d1, borrow)
	s2, borrow = bits.Sub64(s2, d2, borrow)
	s3, borrow = bits.Sub64(s3, 0, borrow)

	// overshoot, add l
	mask := -(borrow & 1)
	s0, carry = bits.Add64(s0, orderLimb0&mask, 0)
	s1, carry = bits.Add64(s1, orderLimb1&mask, carry)
	s2, carry = bits.Add64(s2, orderLimb2&mask, carry)
	s3, _ = bits.Add64(s3, orderLimb3&mask, carry)

	binary.LittleEndian.PutUint64((*s)[:], s0)
	binary.LittleEndian.PutUint64((*s)[8:], s1)
	binary.LittleEndian.PutUint64((*s)[16:], s2)
	binary.LittleEndian.PutUint64((*s)[24:], s3)
}

// BytesToScalar64 Reduces a 512-bit little endian scalar mod order
//
// Constant time
//
//go:nosplit
func BytesToScalar64(c *Scalar, buf [64]byte) {
	_, _ = c.SetWideBytes(buf[:])
}

// BytesToScalar32 Reduces a 256-bit little endian scalar mod order
//
// Constant time
//
//go:nosplit
func BytesToScalar32(c *Scalar, buf [32]byte) {
	ScalarReduce32(&buf)
	_, _ = c.SetBytes(buf[:])
}

var zeroScalar = ZeroPrivateKeyBytes.Scalar()
