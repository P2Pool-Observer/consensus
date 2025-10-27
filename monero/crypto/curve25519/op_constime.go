package curve25519

// ConstantTimeOperations Implements Constant time operations for Edwards25519 points
//
// Safe to use with private data or scalars
type ConstantTimeOperations struct{}

func (e ConstantTimeOperations) Add(v *Point, p, q *Point) *Point {
	return v.Add(p, q)
}

func (e ConstantTimeOperations) Subtract(v *Point, p, q *Point) *Point {
	return v.Subtract(p, q)
}

func (e ConstantTimeOperations) ScalarBaseMult(v *Point, x *Scalar) *Point {
	return v.ScalarBaseMult(x)
}

func (e ConstantTimeOperations) ScalarMult(v *Point, x *Scalar, q *Point) *Point {
	return v.ScalarMult(x, q)
}

func (e ConstantTimeOperations) ScalarMultPrecomputed(v *Point, x *Scalar, q *Generator) *Point {
	return v.ScalarMultPrecomputed(x, q.Table)
}

func (e ConstantTimeOperations) DoubleScalarBaseMult(v *Point, a *Scalar, A *Point, b *Scalar) *Point {
	aA := new(Point).ScalarMult(a, A)
	bG := new(Point).ScalarBaseMult(b)
	return v.Add(aA, bG)
}

func (e ConstantTimeOperations) DoubleScalarBaseMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar) *Point {
	aA := new(Point).ScalarMultPrecomputed(a, A.Table)
	bG := new(Point).ScalarBaseMult(b)
	return v.Add(aA, bG)
}

func (e ConstantTimeOperations) DoubleScalarMult(v *Point, a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	aA := new(Point).ScalarMult(a, A)
	bB := new(Point).ScalarMult(b, B)
	return v.Add(aA, bB)
}

func (e ConstantTimeOperations) DoubleScalarMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar, B *Generator) *Point {
	aA := new(Point).ScalarMultPrecomputed(a, A.Table)
	bB := new(Point).ScalarMultPrecomputed(b, B.Table)
	return v.Add(aA, bB)
}

func (e ConstantTimeOperations) DoubleScalarMultPrecomputedB(v *Point, a *Scalar, A *Point, b *Scalar, B *Generator) *Point {
	aA := new(Point).ScalarMult(a, A)
	bB := new(Point).ScalarMultPrecomputed(b, B.Table)
	return v.Add(aA, bB)
}

func (e ConstantTimeOperations) MultiScalarMult(v *Point, scalars []*Scalar, points []*Point) *Point {
	return v.MultiScalarMult(scalars, points)
}

func (e ConstantTimeOperations) IsSmallOrder(v *Point) bool {
	return v.IsSmallOrder()
}

func (e ConstantTimeOperations) IsTorsionFree(v *Point) bool {
	return v.IsTorsionFree()
}

var _ PointOperations = ConstantTimeOperations{}
