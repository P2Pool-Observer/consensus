package curve

type Field[F any] interface {
	*F

	// Operations

	Add(*F, *F) *F
	Subtract(*F, *F) *F
	Multiply(*F, *F) *F
	Square(*F) *F
	Negate(*F) *F
	Invert(*F) *F
	Absolute(*F) *F
	Sqrt(*F) *F

	// Marshaling

	SetBytes([]byte) (*F, error)
	SetWideBytes([]byte) (*F, error)
	Bytes() []byte

	// Setters

	Set(*F) *F
	Select(*F, *F, int) *F
	Zero() *F
	One() *F

	// Comparison

	IsNegative() int
	Equal(*F) int
}
