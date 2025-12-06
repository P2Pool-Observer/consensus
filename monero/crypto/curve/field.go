package curve

type BasicField[F any] interface {
	*F

	// Operations

	Add(a, b *F) *F
	Subtract(a, b *F) *F
	Multiply(a, b *F) *F
	Negate(x *F) *F
	Invert(x *F) *F

	// Setters

	Set(x *F) *F
	Select(a, b *F, cond int) *F
	Zero() *F
	One() *F

	// Comparison
	Equal(x *F) int
}

// Field A full implementation of a Field element with helper utilities
type Field[F any] interface {
	BasicField[F]

	// Operations
	Square(x *F) *F
	Absolute(x *F) *F
	Sqrt(x *F) *F

	// Marshaling

	SetBytes(x []byte) (*F, error)
	SetWideBytes(x []byte) (*F, error)
	Bytes() []byte

	// Comparison
	IsZero() int
	IsNegative() int
}
