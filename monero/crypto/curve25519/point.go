package curve25519

import (
	"crypto/subtle"
	"errors"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/edwards25519"       //nolint:depguard
	"git.gammaspectra.live/P2Pool/edwards25519/field" //nolint:depguard
)

// Point represents a point on the edwards25519 curve.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is NOT valid, and it may be used only as a receiver.
//
// Mostly a passthrough implementation of edwards25519/Point
type Point edwards25519.Point

type VarTimePoint = curve.VarTimePoint[Point, Scalar, *Point, *Scalar]

var EightTorsion = *(*[8]*Point)(unsafe.Pointer(&edwards25519.EightTorsion))

func NewGeneratorPoint() *Point {
	return (*Point)(edwards25519.NewGeneratorPoint())
}

var identity = NewIdentityPoint()

func NewIdentityPoint() *Point {
	return (*Point)(edwards25519.NewIdentityPoint())
}

func (v *Point) P() *edwards25519.Point {
	return (*edwards25519.Point)(v)
}

func (v *Point) Set(u *Point) *Point {
	*v = *u
	return v
}

//go:nosplit
func (v *Point) Bytes() []byte {
	return v.P().Bytes()
}

//go:nosplit
func (v *Point) BytesMontgomery() []byte {
	return v.P().BytesMontgomery()
}

func (v *Point) SetBytes(x []byte) (*Point, error) {
	ret, err := v.P().SetBytes(x)
	if err != nil {
		return nil, err
	}

	// Ban points which are either unreduced or -0
	if subtle.ConstantTimeCompare(ret.Bytes(), x) == 0 {
		return nil, errors.New("invalid point encoding")
	}
	return (*Point)(ret), nil
}

func (v *Point) SetCanonicalBytesVarTime(x []byte) (*Point, error) {
	ret, err := v.P().SetCanonicalBytesVarTime(x)
	return (*Point)(ret), err
}

func (v *Point) Add(p, q *Point) *Point {
	return (*Point)(v.P().Add(p.P(), q.P()))
}

func (v *Point) Subtract(p, q *Point) *Point {
	return (*Point)(v.P().Subtract(p.P(), q.P()))
}

func (v *Point) Negate(u *Point) *Point {
	return (*Point)(v.P().Negate(u.P()))
}

func (v *Point) Equal(u *Point) int {
	return v.P().Equal(u.P())
}

func (v *Point) ExtendedCoordinates() (X, Y, Z, T *field.Element) {
	return v.P().ExtendedCoordinates()
}

func (v *Point) SetExtendedCoordinates(X, Y, Z, T *field.Element) (*Point, error) {
	ret, err := v.P().SetExtendedCoordinates(X, Y, Z, T)
	return (*Point)(ret), err
}

func (v *Point) MultByCofactor(p *Point) *Point {
	return (*Point)(v.P().MultByCofactor(p.P()))
}

func (v *Point) MultiScalarMult(scalars []*Scalar, points []*Point) *Point {
	return (*Point)(v.P().MultiScalarMult(
		// #nosec G103 -- direct type cast, same length
		unsafe.Slice((**edwards25519.Scalar)(unsafe.Pointer(unsafe.SliceData(scalars))), len(scalars)),
		// #nosec G103 -- direct type cast, same length
		unsafe.Slice((**edwards25519.Point)(unsafe.Pointer(unsafe.SliceData(points))), len(points)),
	))
}

func (v *Point) VarTimeMultiScalarMultPippenger(scalars []*Scalar, points []*Point) *Point {
	return (*Point)(v.P().VarTimeMultiScalarMultPippenger(
		// #nosec G103 -- direct type cast, same length
		unsafe.Slice((**edwards25519.Scalar)(unsafe.Pointer(unsafe.SliceData(scalars))), len(scalars)),
		// #nosec G103 -- direct type cast, same length
		unsafe.Slice((**edwards25519.Point)(unsafe.Pointer(unsafe.SliceData(points))), len(points)),
	))
}

func (v *Point) VarTimeMultiScalarMult(scalars []*Scalar, points []*Point) *Point {
	return (*Point)(v.P().VarTimeMultiScalarMult(
		// #nosec G103 -- direct type cast, same length
		unsafe.Slice((**edwards25519.Scalar)(unsafe.Pointer(unsafe.SliceData(scalars))), len(scalars)),
		// #nosec G103 -- direct type cast, same length
		unsafe.Slice((**edwards25519.Point)(unsafe.Pointer(unsafe.SliceData(points))), len(points)),
	))
}

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *Point) Select(a, b *Point, cond int) *Point {
	return (*Point)(v.P().Select(a.P(), b.P(), cond))
}

func (v *Point) Double(p *Point) *Point {
	return (*Point)(v.P().Double(p.P()))
}

func (v *Point) ScalarMultSlow(x *Scalar, q *Point) *Point {
	return (*Point)(v.P().ScalarMultSlow(x.S(), q.P()))
}

func (v *Point) ScalarMultPrecomputed(x *Scalar, table *edwards25519.PrecomputedTable) *Point {
	return (*Point)(v.P().ScalarMultPrecomputed(x.S(), table))
}

func (v *Point) VarTimeScalarMultPrecomputed(x *Scalar, table *edwards25519.PrecomputedTable) *Point {
	return (*Point)(v.P().VarTimeScalarMultPrecomputed(x.S(), table))
}

func (v *Point) VarTimeDoubleScalarBaseMultPrecomputed(a *Scalar, aTable *edwards25519.PrecomputedTable, b *Scalar) *Point {
	return (*Point)(v.P().VarTimeDoubleScalarBaseMultPrecomputed(a.S(), aTable, b.S()))
}

func (v *Point) VarTimeDoubleScalarMult(a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	return (*Point)(v.P().VarTimeDoubleScalarMult(a.S(), A.P(), b.S(), B.P()))
}

func (v *Point) VarTimeDoubleScalarMultPrecomputed(a *Scalar, aTable *edwards25519.PrecomputedTable, b *Scalar, bTable *edwards25519.PrecomputedTable) *Point {
	return (*Point)(v.P().VarTimeDoubleScalarMultPrecomputed(a.S(), aTable, b.S(), bTable))
}

func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	return (*Point)(v.P().ScalarBaseMult(x.S()))
}

func (v *Point) VarTimeScalarBaseMult(x *Scalar) *Point {
	return (*Point)(v.P().VarTimeScalarBaseMult(x.S()))
}

func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	return (*Point)(v.P().ScalarMult(x.S(), q.P()))
}

func (v *Point) VarTimeScalarMult(x *Scalar, q *Point) *Point {
	return (*Point)(v.P().VarTimeScalarMult(x.S(), q.P()))
}

func (v *Point) VarTimeDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar) *Point {
	return (*Point)(v.P().VarTimeDoubleScalarBaseMult(a.S(), A.P(), b.S()))
}

func (v *Point) IsSmallOrder() bool {
	return v.P().IsSmallOrder()
}

func (v *Point) IsTorsionFree() bool {
	return v.P().IsTorsionFree()
}

func (v *Point) IsTorsionFreeVarTime() bool {
	return v.P().IsTorsionFreeVarTime()
}

func (v *Point) MultByPrimeOrder(p *Point) *Point {
	return (*Point)(v.P().MultByPrimeOrder(p.P()))
}

func (v *Point) Identity() *Point {
	return v.Set(identity)
}

func (v *Point) IsIdentity() int {
	return v.Equal(identity)
}

func (v *Point) DoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar) *Point {
	aA := new(Point).ScalarMult(a, A)
	bG := new(Point).ScalarBaseMult(b)
	return v.Add(aA, bG)
}

func (v *Point) DoubleScalarBaseMultPrecomputed(a *Scalar, aTable *edwards25519.PrecomputedTable, b *Scalar) *Point {
	aA := new(Point).ScalarMultPrecomputed(a, aTable)
	bG := new(Point).ScalarBaseMult(b)
	return v.Add(aA, bG)
}

func (v *Point) DoubleScalarMult(a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	aA := new(Point).ScalarMult(a, A)
	bG := new(Point).ScalarMult(b, B)
	return v.Add(aA, bG)
}
