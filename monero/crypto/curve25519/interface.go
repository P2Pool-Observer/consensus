package curve25519

import (
	_ "unsafe"
)

type PointOperations interface {
	Add(v *Point, p, q *Point) *Point
	Subtract(v *Point, p, q *Point) *Point
	Double(v *Point, x *Point) *Point
	Negate(v *Point, x *Point) *Point

	MultByCofactor(v *Point, x *Point) *Point

	ScalarBaseMult(v *Point, x *Scalar) *Point

	ScalarMult(v *Point, x *Scalar, q *Point) *Point
	ScalarMultPrecomputed(v *Point, x *Scalar, q *Generator) *Point

	DoubleScalarBaseMult(v *Point, a *Scalar, A *Point, b *Scalar) *Point
	DoubleScalarBaseMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar) *Point

	DoubleScalarMult(v *Point, a *Scalar, A *Point, b *Scalar, B *Point) *Point
	DoubleScalarMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar, B *Generator) *Point
	DoubleScalarMultPrecomputedB(v *Point, a *Scalar, A *Point, b *Scalar, B *Generator) *Point

	MultiScalarMult(v *Point, scalars []*Scalar, points []*Point) *Point

	IsSmallOrder(v *Point) bool
	IsTorsionFree(v *Point) bool

	SetBytes(v *Point, x []byte) (*Point, error)
}

// TODO: Remove this noescape obscuring when Go 1.26+ fixes heap escape of generic calls
// We avoid triggering heap allocations in hot code by passing it through a linkname -> noescape stub
// See https://github.com/golang/go/issues/48849
// See https://github.com/golang/go/issues/75056

func _add(op PointOperations, v *Point, p, q *Point) *Point {
	return op.Add(v, p, q)
}

//go:noescape
//go:linkname add git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._add
func add(op PointOperations, v *Point, p, q *Point) *Point

func _subtract(op PointOperations, v *Point, p, q *Point) *Point {
	return op.Subtract(v, p, q)
}

//go:noescape
//go:linkname subtract git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._subtract
func subtract(op PointOperations, v *Point, p, q *Point) *Point

func _double(op PointOperations, v *Point, x *Point) *Point {
	return op.Double(v, x)
}

//go:noescape
//go:linkname double git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._double
func double(op PointOperations, v *Point, x *Point) *Point

func _negate(op PointOperations, v *Point, x *Point) *Point {
	return op.Negate(v, x)
}

//go:noescape
//go:linkname negate git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._negate
func negate(op PointOperations, v *Point, x *Point) *Point

func _multByCofactor(op PointOperations, v *Point, x *Point) *Point {
	return op.MultByCofactor(v, x)
}

//go:noescape
//go:linkname multByCofactor git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._multByCofactor
func multByCofactor(op PointOperations, v *Point, x *Point) *Point

func _scalarBaseMult(op PointOperations, v *Point, x *Scalar) *Point {
	return op.ScalarBaseMult(v, x)
}

//go:noescape
//go:linkname scalarBaseMult git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._scalarBaseMult
func scalarBaseMult(op PointOperations, v *Point, x *Scalar) *Point

func _scalarMult(op PointOperations, v *Point, x *Scalar, q *Point) *Point {
	return op.ScalarMult(v, x, q)
}

//go:noescape
//go:linkname scalarMult git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._scalarMult
func scalarMult(op PointOperations, v *Point, x *Scalar, q *Point) *Point

func _scalarMultPrecomputed(op PointOperations, v *Point, x *Scalar, q *Generator) *Point {
	return op.ScalarMultPrecomputed(v, x, q)
}

//go:noescape
//go:linkname scalarMultPrecomputed git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._scalarMultPrecomputed
func scalarMultPrecomputed(op PointOperations, v *Point, x *Scalar, q *Generator) *Point

func _doubleScalarBaseMult(op PointOperations, v *Point, a *Scalar, A *Point, b *Scalar) *Point {
	return op.DoubleScalarBaseMult(v, a, A, b)
}

//go:noescape
//go:linkname doubleScalarBaseMult git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._doubleScalarBaseMult
func doubleScalarBaseMult(op PointOperations, v *Point, a *Scalar, A *Point, b *Scalar) *Point

func _doubleScalarBaseMultPrecomputed(op PointOperations, v *Point, a *Scalar, A *Generator, b *Scalar) *Point {
	return op.DoubleScalarBaseMultPrecomputed(v, a, A, b)
}

//go:noescape
//go:linkname doubleScalarBaseMultPrecomputed git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._doubleScalarBaseMultPrecomputed
func doubleScalarBaseMultPrecomputed(op PointOperations, v *Point, a *Scalar, A *Generator, b *Scalar) *Point

func _doubleScalarMultPrecomputed(op PointOperations, v *Point, a *Scalar, A *Generator, b *Scalar, B *Generator) *Point {
	return op.DoubleScalarMultPrecomputed(v, a, A, b, B)
}

func _doubleScalarMult(op PointOperations, v *Point, a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	return op.DoubleScalarMult(v, a, A, b, B)
}

//go:noescape
//go:linkname doubleScalarMult git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._doubleScalarMult
func doubleScalarMult(op PointOperations, v *Point, a *Scalar, A *Point, b *Scalar, B *Point) *Point

//go:noescape
//go:linkname doubleScalarMultPrecomputed git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._doubleScalarMultPrecomputed
func doubleScalarMultPrecomputed(op PointOperations, v *Point, a *Scalar, A *Generator, b *Scalar, B *Generator) *Point

func _doubleScalarMultPrecomputedB(op PointOperations, v *Point, a *Scalar, A *Point, b *Scalar, B *Generator) *Point {
	return op.DoubleScalarMultPrecomputedB(v, a, A, b, B)
}

//go:noescape
//go:linkname doubleScalarMultPrecomputedB git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._doubleScalarMultPrecomputedB
func doubleScalarMultPrecomputedB(op PointOperations, v *Point, a *Scalar, A *Point, b *Scalar, B *Generator) *Point

func _isSmallOrder(op PointOperations, v *Point) bool {
	return op.IsSmallOrder(v)
}

//go:noescape
//go:linkname isSmallOrder git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._isSmallOrder
func isSmallOrder(op PointOperations, v *Point) bool

func _isTorsionFree(op PointOperations, v *Point) bool {
	return op.IsTorsionFree(v)
}

//go:noescape
//go:linkname isTorsionFree git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._isTorsionFree
func isTorsionFree(op PointOperations, v *Point) bool

func _setBytes(op PointOperations, v *Point, x []byte) (*Point, error) {
	return op.SetBytes(v, x)
}

//go:noescape
//go:linkname setBytes git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519._setBytes
func setBytes(op PointOperations, v *Point, x []byte) (*Point, error)
