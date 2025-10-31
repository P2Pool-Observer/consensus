package curve25519

// VarTimeOperations Implements Variable time operations for Edwards25519 points
// Some operations may be implemented as constant time operations if no variable alternative exists
//
// Unsafe to use with private data or scalars
type VarTimeOperations struct{}

func (e VarTimeOperations) Add(v *Point, p, q *Point) *Point {
	return v.Add(p, q)
}

func (e VarTimeOperations) Subtract(v *Point, p, q *Point) *Point {
	return v.Subtract(p, q)
}

func (e VarTimeOperations) Double(v *Point, x *Point) *Point {
	return v.Double(x)
}

func (e VarTimeOperations) Negate(v *Point, x *Point) *Point {
	return v.Negate(x)
}

func (e VarTimeOperations) MultByCofactor(v *Point, x *Point) *Point {
	return v.MultByCofactor(x)
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

func (e VarTimeOperations) DoubleScalarMultPrecomputedB(v *Point, a *Scalar, A *Point, b *Scalar, B *Generator) *Point {
	aA := new(Point).VarTimeScalarMult(a, A)
	bB := new(Point).VarTimeScalarMultPrecomputed(b, B.Table)
	return v.Add(aA, bB)
}

func (e VarTimeOperations) MultiScalarMult(v *Point, scalars []*Scalar, points []*Point) *Point {
	return v.VarTimeMultiScalarMult(scalars, points)
}

func (e VarTimeOperations) IsSmallOrder(v *Point) bool {
	return v.IsSmallOrder()
}

func (e VarTimeOperations) IsTorsionFree(v *Point) bool {
	return v.IsTorsionFreeVarTime()
}

// SetBytes sets v = x, where x is a 32-byte encoding of v. If x does not
// represent a valid point on the curve, SetBytes returns nil and an error and
// the receiver is unchanged. Otherwise, SetBytes returns v.
//
// Note that SetBytes accepts all non-canonical encodings of valid points.
// That is, it follows decoding rules that match most implementations in
// the ecosystem rather than RFC 8032.
//
// Variable time
func (e VarTimeOperations) SetBytes(v *Point, x []byte) (*Point, error) {
	return v.SetCanonicalBytesVarTime(x)
}

var _ PointOperations = VarTimeOperations{}

func init() {
	assertSize[VarTimeOperations]()
}
