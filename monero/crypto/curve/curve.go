package curve

type Ciphersuite[P any, F any] interface {
	// A in the curve equation `y^2 = x^3 + A x + B`
	A() *F
	// B in the curve equation `y^2 = x^3 + A x + B`
	B() *F

	Generator() *P

	ScalarBits() int

	// XY Convert a point to its affine coordinates.
	XY(v *P) (x, y F, err error)
}
