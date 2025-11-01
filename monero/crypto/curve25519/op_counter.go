package curve25519

import "sync/atomic"

// VarTimeCounterOperations Is like VarTimeOperations, but increases a global counter for tests
//
// Unsafe to use with private data or scalars
type VarTimeCounterOperations struct{}

var counterOp VarTimeOperations

var (
	counterAddSub       atomic.Uint64
	counterDouble       atomic.Uint64
	counterNegate       atomic.Uint64
	counterCofactorMult atomic.Uint64
	counterScalarMult   atomic.Uint64
	counterTorsion      atomic.Uint64
)

func VarTimeCounterOperationsReset() {
	counterAddSub.Store(0)
	counterDouble.Store(0)
	counterNegate.Store(0)
	counterCofactorMult.Store(0)
	counterScalarMult.Store(0)
	counterTorsion.Store(0)
}

func VarTimeCounterOperationsReport(N int, f func(v float64, metric string)) {
	report := func(v uint64, metric string) {
		if v == 0 {
			return
		}
		if v%uint64(N) == 0 {
			f(float64(v/uint64(N)), metric+"/op")
			return
		}
		f(float64(v)/float64(N), metric+"/op")
	}

	report(counterAddSub.Load(), "AddSub")
	report(counterDouble.Load(), "Double")
	report(counterNegate.Load(), "Negate")
	report(counterCofactorMult.Load(), "CofactorMult")
	report(counterScalarMult.Load(), "ScalarMult")
	report(counterTorsion.Load(), "Torsion")
}

func (e VarTimeCounterOperations) Add(v *Point, p, q *Point) *Point {
	counterAddSub.Add(1)
	return counterOp.Add(v, p, q)
}

func (e VarTimeCounterOperations) Subtract(v *Point, p, q *Point) *Point {
	counterAddSub.Add(1)
	return counterOp.Subtract(v, p, q)
}

func (e VarTimeCounterOperations) Double(v *Point, x *Point) *Point {
	counterDouble.Add(1)
	return counterOp.Double(v, x)
}

func (e VarTimeCounterOperations) Negate(v *Point, x *Point) *Point {
	counterNegate.Add(1)
	return counterOp.Negate(v, x)
}

func (e VarTimeCounterOperations) MultByCofactor(v *Point, x *Point) *Point {
	counterCofactorMult.Add(1)
	return counterOp.MultByCofactor(v, x)
}

func (e VarTimeCounterOperations) ScalarBaseMult(v *Point, x *Scalar) *Point {
	counterScalarMult.Add(1)
	return counterOp.ScalarBaseMult(v, x)
}

func (e VarTimeCounterOperations) ScalarMult(v *Point, x *Scalar, q *Point) *Point {
	counterScalarMult.Add(1)
	return counterOp.ScalarMult(v, x, q)
}

func (e VarTimeCounterOperations) ScalarMultPrecomputed(v *Point, x *Scalar, q *Generator) *Point {
	counterScalarMult.Add(1)
	return counterOp.ScalarMultPrecomputed(v, x, q)
}

func (e VarTimeCounterOperations) DoubleScalarBaseMult(v *Point, a *Scalar, A *Point, b *Scalar) *Point {
	counterScalarMult.Add(2)
	counterAddSub.Add(1)
	return counterOp.DoubleScalarBaseMult(v, a, A, b)
}

func (e VarTimeCounterOperations) DoubleScalarBaseMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar) *Point {
	counterScalarMult.Add(2)
	counterAddSub.Add(1)
	return counterOp.DoubleScalarBaseMultPrecomputed(v, a, A, b)
}

func (e VarTimeCounterOperations) DoubleScalarMult(v *Point, a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	counterScalarMult.Add(2)
	counterAddSub.Add(1)
	return counterOp.DoubleScalarMult(v, a, A, b, B)
}

func (e VarTimeCounterOperations) DoubleScalarMultPrecomputed(v *Point, a *Scalar, A *Generator, b *Scalar, B *Generator) *Point {
	counterScalarMult.Add(2)
	counterAddSub.Add(1)
	return counterOp.DoubleScalarMultPrecomputed(v, a, A, b, B)
}

func (e VarTimeCounterOperations) DoubleScalarMultPrecomputedB(v *Point, a *Scalar, A *Point, b *Scalar, B *Generator) *Point {
	counterScalarMult.Add(2)
	counterAddSub.Add(1)
	return counterOp.DoubleScalarMultPrecomputedB(v, a, A, b, B)
}

func (e VarTimeCounterOperations) MultiScalarMult(v *Point, scalars []*Scalar, points []*Point) *Point {
	counterScalarMult.Add(uint64(len(scalars)))
	counterAddSub.Add(uint64(max(0, len(scalars)-1)))
	return counterOp.MultiScalarMult(v, scalars, points)
}

func (e VarTimeCounterOperations) IsSmallOrder(v *Point) bool {
	counterCofactorMult.Add(1)
	return counterOp.IsSmallOrder(v)
}

func (e VarTimeCounterOperations) IsTorsionFree(v *Point) bool {
	counterTorsion.Add(1)
	return counterOp.IsTorsionFree(v)
}

func (e VarTimeCounterOperations) SetBytes(v *Point, x []byte) (*Point, error) {
	return counterOp.SetBytes(v, x)
}

var _ PointOperations = VarTimeCounterOperations{}

func init() {
	assertSize[VarTimeCounterOperations]()
}
