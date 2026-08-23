package divisors

import (
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type Evals[F any] struct {
	Evals  []F
	Degree int
}

func NewEvalsFromDegree1[F any, FE curve.BasicField[F]](coeff, constant *F, amountOfEvals int) Evals[F] {
	if amountOfEvals == 0 {
		return Evals[F]{
			Degree: 1,
		}
	}
	lastEval := *constant

	evals := make([]F, 0, amountOfEvals)
	for range amountOfEvals {
		evals = append(evals, lastEval)
		FE(&lastEval).Add(&lastEval, coeff)
	}
	return Evals[F]{
		Evals:  evals,
		Degree: 1,
	}
}

func NewEvalsFromDegree0[F any](constant *F, amountOfEvals int) Evals[F] {
	if amountOfEvals == 0 {
		return Evals[F]{
			Degree: 0,
		}
	}

	evals := make([]F, 0, amountOfEvals)
	for range amountOfEvals {
		evals = append(evals, *constant)
	}

	return Evals[F]{
		Evals:  evals,
		Degree: 0,
	}
}

type SmallDivisor[F any] struct {
	XCoefficient    F
	ZeroCoefficient F
	YCoefficient    F
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (d *SmallDivisor[F]) Select[FE curve.BasicField[F]](a, b *SmallDivisor[F], cond int) *SmallDivisor[F] {
	FE(&d.XCoefficient).Select(&a.XCoefficient, &b.XCoefficient, cond)
	FE(&d.ZeroCoefficient).Select(&a.ZeroCoefficient, &b.ZeroCoefficient, cond)
	FE(&d.YCoefficient).Select(&a.YCoefficient, &b.YCoefficient, cond)
	return d
}

type Divisor[F any] struct {
	A Evals[F]
	B Evals[F]
}

func (d *Divisor[F]) Div[FE curve.BasicField[F]](rhs Evals[F]) *Divisor[F] {
	evalsDen := slices.Clone(rhs.Evals)
	curve.BatchInvert[F, FE](new(F), utils.ValuesToPointers(evalsDen)...)

	for i := range d.A.Evals {
		FE(&d.A.Evals[i]).Multiply(&d.A.Evals[i], &evalsDen[i])
		FE(&d.B.Evals[i]).Multiply(&d.B.Evals[i], &evalsDen[i])
	}

	d.A.Degree -= rhs.Degree
	d.B.Degree -= rhs.Degree

	return d
}

func ComputeModulus[F any, FE curve.Field[F]](a, b *F, amountOfEvals int) Evals[F] {
	// x^3 + ax + b
	evals := make([]F, 0, amountOfEvals)
	for i := range amountOfEvals {
		x := curve.FieldFromUint64[F, FE](new(F), uint64(i))
		cube := FE(new(F)).Multiply(FE(new(F)).Square(x), x)
		ax := FE(new(F)).Multiply(x, a)
		eq := FE(new(F)).Add(cube, ax)
		FE(eq).Add(eq, b)
		evals = append(evals, *eq)
	}

	return Evals[F]{
		Evals:  evals,
		Degree: 3,
	}
}

func NewDivisorFromSmall[F any, FE curve.BasicField[F]](small *SmallDivisor[F], modulus Evals[F]) *Divisor[F] {
	return &Divisor[F]{
		A: NewEvalsFromDegree1[F, FE](&small.XCoefficient, &small.ZeroCoefficient, len(modulus.Evals)),
		B: NewEvalsFromDegree0[F](&small.YCoefficient, len(modulus.Evals)),
	}
}

func (d *Divisor[F]) AB(i int) (a, b *F) {
	return &d.A.Evals[i], &d.B.Evals[i]
}

func (d *Divisor[F]) DegreeAfterMultiplication(otherADegree, otherBDegree int) (a, b int) {
	// f1 * f2 = A1A2 - y(A1B2 + A2B1) + (x^3 + ax + b) B1B2
	// A = A1A2 + (x^3 + ax + b) B1B2
	// B = A1B2 + A2B1
	// deg(A) = max(A1 + A2, 3 + B1 + B2)
	// deg(B) = max(A1 + B2, A2 + B1)
	a1, b1 := d.A.Degree, d.B.Degree
	a2, b2 := otherADegree, otherBDegree
	a = max(a1+a2, 3+b1+b2)
	b = max(a1+b2, a2+b1)

	return a, b
}

func (d *Divisor[F]) MultiplyMod[FE curve.BasicField[F]](rhs *Divisor[F], modulus Evals[F]) *Divisor[F] {

	degreeAfterMultiplicationA, degreeAfterMultiplicationB := d.DegreeAfterMultiplication(rhs.A.Degree, rhs.B.Degree)
	// f1 * f2 = A1A2 - y(A1B2 + A2B1) + y^2 B1B2
	// f1 * f2 = A1A2 - y(A1B2 + A2B1) + (x^3 + ax + b) B1B2
	// (A1+B1)(A2+B2)
	// A1A2 + A1B2 + B1A2 + B1B2
	for i := range d.A.Evals {
		modulus := &modulus.Evals[i]
		a1, b1 := d.AB(i)
		a2, b2 := rhs.AB(i)
		a1a2 := FE(new(F)).Multiply(a1, a2)
		b1b2 := FE(new(F)).Multiply(b1, b2)
		// (A1+B1)(A2+B2)
		cross := FE(new(F)).Multiply(FE(new(F)).Add(a1, b1), FE(new(F)).Add(a2, b2))

		FE(b1).Subtract(cross, FE(new(F)).Add(a1a2, b1b2))
		FE(a1).Add(a1a2, FE(new(F)).Multiply(b1b2, modulus))
	}

	d.A.Degree = degreeAfterMultiplicationA
	d.B.Degree = degreeAfterMultiplicationB

	return d
}

func (d *Divisor[F]) MultiplyModSmall[FE curve.BasicField[F]](rhs *SmallDivisor[F], modulus Evals[F]) *Divisor[F] {
	degreeAfterMultiplicationA, degreeAfterMultiplicationB := d.DegreeAfterMultiplication(1, 0)
	// constant term for x = 0
	a2 := rhs.ZeroCoefficient
	b2 := rhs.YCoefficient
	for i := range d.A.Evals {
		modulus := &modulus.Evals[i]
		a1, b1 := d.AB(i)
		a1a2 := FE(new(F)).Multiply(a1, &a2)
		b1b2 := FE(new(F)).Multiply(b1, &b2)
		// (A1+B1)(A2+B2)
		cross := FE(new(F)).Multiply(FE(new(F)).Add(a1, b1), FE(new(F)).Add(&a2, &b2))

		FE(&a2).Add(&a2, &rhs.XCoefficient)
		FE(b1).Subtract(cross, FE(new(F)).Add(a1a2, b1b2))
		FE(a1).Add(a1a2, FE(new(F)).Multiply(b1b2, modulus))
	}

	d.A.Degree = degreeAfterMultiplicationA
	d.B.Degree = degreeAfterMultiplicationB

	return d
}

// RemoveDifference Remove 2 points by dividing by `(x - x1) * (x - x2)`
func (d *Divisor[F]) RemoveDifference[FE curve.BasicField[F]](x1, x2 utils.ConstantOption[F, FE]) *Divisor[F] {
	denominator := make([]F, 0, len(d.A.Evals))

	var x_l, x_r, inc_l, inc_r, _x1, _x2 F
	FE(&x_l).Zero()
	FE(&x_r).Zero()

	neg1 := FE(new(F)).Negate(FE(new(F)).One())

	_x1 = *x1.UnwrapOr(neg1)
	_x2 = *x2.UnwrapOr(neg1)
	FE(&inc_l).Select(FE(new(F)).One(), FE(new(F)).Zero(), x1.IsSome())
	FE(&inc_r).Select(FE(new(F)).One(), FE(new(F)).Zero(), x2.IsSome())

	for range d.A.Evals {
		denominator = append(denominator, *FE(new(F)).Multiply(FE(new(F)).Subtract(&x_l, &_x1), FE(new(F)).Subtract(&x_r, &_x2)))
		FE(&x_l).Add(&x_l, &inc_l)
		FE(&x_r).Add(&x_r, &inc_r)
	}

	return d.Div[FE](Evals[F]{
		Evals:  denominator,
		Degree: 2,
	})
}

func (d *Divisor[F]) Clone() *Divisor[F] {
	return &Divisor[F]{
		A: Evals[F]{
			Evals:  slices.Clone(d.A.Evals),
			Degree: d.A.Degree,
		},
		B: Evals[F]{
			Evals:  slices.Clone(d.B.Evals),
			Degree: d.B.Degree,
		},
	}
}

func MergeDivisors[F any, FE curve.BasicField[F]](d0, d1 *Divisor[F], small *SmallDivisor[F], denom1, denom2 utils.ConstantOption[F, FE], modulus Evals[F]) *Divisor[F] {
	numerator := d0.Clone().MultiplyMod[FE](d1, modulus).MultiplyModSmall[FE](small, modulus)
	return numerator.RemoveDifference[FE](denom1, denom2)
}

func (d *Divisor[F]) Interpolate[FE curve.BasicField[F]](interpolator *Interpolator[F]) (a, b []F) {
	if max(d.A.Degree, d.B.Degree) > interpolator.Degree() {
		return nil, nil
	}

	return interpolator.Interpolate[FE](d.A.Evals), interpolator.Interpolate[FE](d.A.Evals)
}
