package curve

type Field[F any] interface {
	*F

	// Operations

	Add(a, b *F) *F
	Subtract(a, b *F) *F
	Multiply(a, b *F) *F
	Square(x *F) *F
	Negate(x *F) *F
	Invert(x *F) *F
	Absolute(x *F) *F
	Sqrt(x *F) *F

	// Marshaling

	SetBytes(x []byte) (*F, error)
	SetWideBytes(x []byte) (*F, error)
	Bytes() []byte

	// Setters

	Set(x *F) *F
	Select(a, b *F, cond int) *F
	Zero() *F
	One() *F

	// Comparison

	IsNegative() int
	Equal(x *F) int
}
