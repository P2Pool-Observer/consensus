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

	MultiScalarMult(v *Point, scalars []*Scalar, points []*Point) *Point

	IsSmallOrder(v *Point) bool
	IsTorsionFree(v *Point) bool
}

// https://github.com/golang/go/issues/48849
