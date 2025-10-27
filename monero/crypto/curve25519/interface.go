package curve25519

import (
	_ "unsafe"
)

type PointOperations interface {
	Add(v *Point, p, q *Point) *Point
	Subtract(v *Point, p, q *Point) *Point

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
