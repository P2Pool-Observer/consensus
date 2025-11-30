package curve

type Point[P any] interface {
	*P

	// Operations

	Add(*P, *P) *P
	Subtract(*P, *P) *P
	Double(*P) *P
	Negate(*P) *P

	// Marshaling

	SetBytes([]byte) (*P, error)
	Bytes() []byte

	// Setters

	Set(*P) *P
	Identity() *P

	// Comparison

	IsIdentity() int
	Equal(*P) int
}

type CurvePoint[P any, S any] interface {
	Point[P]

	// Multiplication operations

	ScalarBaseMult(*S) *P
	ScalarMult(*S, *P) *P
}

type ExtraCurvePoint[P any, S any] interface {
	CurvePoint[P, S]

	// Optimized Multiplication operations

	DoubleScalarBaseMult(a *S, A *P, b *S) *P
	DoubleScalarMult(a *S, A *P, b *S, B *P) *P

	MultiScalarMult([]*S, []*P) *P
}

type VarTimeCurvePoint[P any, S any] interface {
	Point[P]

	// Multiplication operations

	VarTimeScalarBaseMult(*S) *P
	VarTimeScalarMult(*S, *P) *P
}

type VarTimeExtraCurvePoint[P any, S any] interface {
	VarTimeCurvePoint[P, S]

	// Optimized Multiplication operations

	VarTimeDoubleScalarBaseMult(a *S, A *P, b *S) *P
	VarTimeDoubleScalarMult(a *S, A *P, b *S, B *P) *P

	VarTimeMultiScalarMult([]*S, []*P) *P
}
