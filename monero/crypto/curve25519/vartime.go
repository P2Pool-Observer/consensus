package curve25519

type VarTimeOperations struct{}

func (e VarTimeOperations) Add(v *Point, p, q *Point) *Point {
	return v.Add(p, q)
}

func (e VarTimeOperations) Subtract(v *Point, p, q *Point) *Point {
	return v.Subtract(p, q)
}

func (e VarTimeOperations) ScalarBaseMult(v *Point, x *Scalar) *Point {
	return v.VarTimeScalarBaseMult(x)
}

func (e VarTimeOperations) ScalarMult(v *Point, x *Scalar, q *Point) *Point {
	return v.VarTimeScalarMult(x, q)
}

func (e VarTimeOperations) ScalarMultPrecomputed(v *Point, x *Scalar, q *Generator) *Point {
	return v.VarTimeScalarMultPrecomputed(x, q.Table)
}

func (e VarTimeOperations) DoubleScalarBaseMult(v *Point, a *Scalar, A *Point, b *Scalar) *Point {
	return v.VarTimeDoubleScalarBaseMult(a, A, b)
}

func (e VarTimeOperations) DoubleScalarBaseMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar) *Point {
	return v.VarTimeDoubleScalarBaseMultPrecomputed(a, A.Table, b)
}

func (e VarTimeOperations) DoubleScalarMult(v *Point, a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	return v.VarTimeDoubleScalarMult(a, A, b, B)
}

func (e VarTimeOperations) DoubleScalarMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar, B *Generator) *Point {
	return v.VarTimeDoubleScalarMultPrecomputed(a, A.Table, b, B.Table)
}

func (e VarTimeOperations) MultiScalarMult(v *Point, scalars []*Scalar, points []*Point) *Point {
	return v.MultiScalarMult(scalars, points)
}

func (e VarTimeOperations) IsSmallOrder(v *Point) bool {
	return v.IsSmallOrder()
}

func (e VarTimeOperations) IsTorsionFree(v *Point) bool {
	return v.IsTorsionFreeVarTime()
}

var _ PointOperations = VarTimeOperations{}
