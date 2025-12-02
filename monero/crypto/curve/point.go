package curve

type Point[P any] interface {
	*P

	// Operations

	Add(a, b *P) *P
	Subtract(a, b *P) *P
	Double(x *P) *P
	Negate(x *P) *P

	// Marshaling

	SetBytes(x []byte) (*P, error)
	Bytes() []byte

	// Setters

	Set(x *P) *P
	Identity() *P

	// Comparison

	IsIdentity() int
	Equal(x *P) int
}

type CurvePoint[P any, S any] interface {
	Point[P]

	// Multiplication operations

	ScalarBaseMult(x *S) *P
	ScalarMult(x *S, X *P) *P
}

type ExtraCurvePoint[P any, S any] interface {
	CurvePoint[P, S]

	// Optimized Multiplication operations

	DoubleScalarBaseMult(a *S, A *P, b *S) *P
	DoubleScalarMult(a *S, A *P, b *S, B *P) *P

	MultiScalarMult(scalars []*S, points []*P) *P
}

type VarTimeCurvePoint[P any, S any] interface {
	Point[P]

	// Multiplication operations

	VarTimeScalarBaseMult(x *S) *P
	VarTimeScalarMult(x *S, X *P) *P
}

type VarTimeExtraCurvePoint[P any, S any] interface {
	VarTimeCurvePoint[P, S]

	// Optimized Multiplication operations

	VarTimeDoubleScalarBaseMult(a *S, A *P, b *S) *P
	VarTimeDoubleScalarMult(a *S, A *P, b *S, B *P) *P

	VarTimeMultiScalarMult(scalars []*S, points []*P) *P
}
