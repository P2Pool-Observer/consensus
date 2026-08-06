package curve

// TODO: use Go 1.26 recursive types

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

type VarTimePoint[P any, S any, PE VarTimeExtraCurvePoint[P, S], SE Scalar[S]] struct {
	p P
}

func (v *VarTimePoint[P, S, PE, SE]) Add(a, b *VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).Add(&a.p, &b.p)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) Subtract(a, b *VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).Subtract(&a.p, &b.p)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) Double(x *VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).Double(&x.p)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) Negate(x *VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).Negate(&x.p)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) SetBytes(x []byte) (*VarTimePoint[P, S, PE, SE], error) {
	_, err := PE(&v.p).SetBytes(x)
	return v, err
}

func (v *VarTimePoint[P, S, PE, SE]) Bytes() []byte {
	return PE(&v.p).Bytes()
}

func (v *VarTimePoint[P, S, PE, SE]) Set(x *VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).Set(&x.p)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) Identity() *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).Identity()
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) IsIdentity() int {
	return PE(&v.p).IsIdentity()
}

func (v *VarTimePoint[P, S, PE, SE]) Equal(x *VarTimePoint[P, S, PE, SE]) int {
	return PE(&v.p).Equal(&x.p)
}

func (v *VarTimePoint[P, S, PE, SE]) ScalarBaseMult(x *S) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).VarTimeScalarBaseMult(x)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) ScalarMult(x *S, X *VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).VarTimeScalarMult(x, &X.p)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) DoubleScalarBaseMult(a *S, A *VarTimePoint[P, S, PE, SE], b *S) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).VarTimeDoubleScalarBaseMult(a, &A.p, b)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) DoubleScalarMult(a *S, A *VarTimePoint[P, S, PE, SE], b *S, B *VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	PE(&v.p).VarTimeDoubleScalarMult(a, &A.p, b, &B.p)
	return v
}

func (v *VarTimePoint[P, S, PE, SE]) MultiScalarMult(scalars []*S, points []*VarTimePoint[P, S, PE, SE]) *VarTimePoint[P, S, PE, SE] {
	entries := make([]*P, len(points))
	for i := range points {
		entries[i] = &points[i].p
	}
	PE(&v.p).VarTimeMultiScalarMult(scalars, entries)
	return v
}
