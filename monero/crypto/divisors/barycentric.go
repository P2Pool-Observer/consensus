package divisors

import (
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type UnivariatePoly[F any] []F

func (p UnivariatePoly[F]) Multiply[FE curve.BasicField[F]](s *F) UnivariatePoly[F] {
	for i := range p {
		FE(&p[i]).Multiply(&p[i], s)
	}
	return p
}

func (p UnivariatePoly[F]) Add[FE curve.BasicField[F]](o UnivariatePoly[F]) UnivariatePoly[F] {
	if len(o) != len(p) {
		panic("len mismatch")
	}
	for i := range min(len(p), len(o)) {
		FE(&p[i]).Add(&p[i], &o[i])
	}
	return p
}

func (p UnivariatePoly[F]) Eval[FE curve.BasicField[F]](x *F) (res F) {
	for i := range p {
		FE(&res).Add(&p[i], FE(new(F)).Multiply(&res, x))
	}
	return res
}

func (p UnivariatePoly[F]) MultiplyXC[FE curve.BasicField[F]](c *F) UnivariatePoly[F] {
	coeffs := append(p, *FE(new(F)).Zero())
	priorCoeff := coeffs[0]

	for i := 1; i < len(coeffs); i++ {
		currentCoeff := coeffs[i]
		FE(&coeffs[i]).Add(&coeffs[i], FE(new(F)).Multiply(&priorCoeff, c))
		priorCoeff = currentCoeff
	}
	return coeffs
}

func (p UnivariatePoly[F]) DivideXC[FE curve.BasicField[F]](c *F) (result UnivariatePoly[F], remainder F) {
	if len(p) == 0 {
		return p, *FE(new(F)).Zero()
	}
	newCoeff := p[0]
	coeffs := p[1:]

	for i := range coeffs {
		currentCoeff := coeffs[i]
		FE(&coeffs[i]).Set(&newCoeff)
		FE(&newCoeff).Subtract(&currentCoeff, FE(new(F)).Multiply(&newCoeff, c))
	}
	return coeffs, newCoeff
}

type Weights[F any] struct {
	InvertedWeights []F
	L               UnivariatePoly[F]
}

func WeightsL[F any, FE curve.Field[F]](domainSize int) UnivariatePoly[F] {
	poly := UnivariatePoly[F]{*FE(new(F)).One()}
	for i := range domainSize {
		f := curve.FieldFromUint64[F, FE](new(F), uint64(i))
		FE(f).Negate(f)
		poly = poly.MultiplyXC[FE](f)
	}
	return poly
}

func NewWeights[F any, FE curve.Field[F]](domainSize int) Weights[F] {
	right := make([]F, domainSize)
	FE(&right[domainSize-1]).One()
	var diff, one F
	FE(&one).One()
	FE(&diff).Negate(FE(new(F)).One())
	for i := domainSize - 2; i >= 0; i-- {
		FE(&right[i]).Multiply(&right[i+1], &diff)
		FE(&diff).Subtract(&diff, &one)
	}

	weights := make([]F, domainSize)
	FE(&weights[0]).Set(&right[0])

	var left F
	FE(&left).One()
	FE(&diff).One()
	for i := 1; i < domainSize; i++ {
		FE(&left).Multiply(&left, &diff)
		FE(&weights[i]).Multiply(&left, &right[i])
		FE(&diff).Add(&diff, &one)
	}

	curve.BatchInvert[F, FE](new(F), utils.ValuesToPointers(weights)...)

	return Weights[F]{
		InvertedWeights: weights,
		L:               WeightsL[F, FE](domainSize),
	}
}

func (w Weights[F]) LI[FE curve.Field[F]](i int) UnivariatePoly[F] {
	{
		iF := FE(new(F)).Negate(curve.FieldFromUint64[F, FE](new(F), uint64(i)))
		li, rem := slices.Clone(w.L).DivideXC[FE](iF)
		// The `l` polynomial is the product of `x - i`, ensuring we can divide out `x - i`
		if FE(&rem).IsZero() == 0 {
			panic("unreachable")
		}
		return li.Multiply[FE](&w.InvertedWeights[i])
	}
}

type Interpolator[F any] struct {
	LarangePolys []UnivariatePoly[F]
}

func NewInterpolator[F any, FE curve.Field[F]](degree int) Interpolator[F] {
	domainSize := degree + 1
	weights := NewWeights[F, FE](domainSize)
	lagrangePolys := make([]UnivariatePoly[F], 0, domainSize)
	for i := range domainSize {
		li := weights.LI[FE](i)
		lagrangePolys = append(lagrangePolys, li)
	}
	return Interpolator[F]{
		LarangePolys: lagrangePolys,
	}
}

func (i Interpolator[F]) Degree() int {
	return len(i.LarangePolys) - 1
}

func (i Interpolator[F]) RequiredEvaluations() int {
	return len(i.LarangePolys)
}

// Interpolate Attempt to reconstruct the original polynomial via interpolation.
//
// The returned polynomial will have its leading coefficient _last_.
//
// Returns `None` if not enough evaluations were provided to attempt interpolation. Returns
// garbage if the polynomial's degree exceeds this interpolator's.
func (i Interpolator[F]) Interpolate[FE curve.BasicField[F]](evals []F) []F {
	if len(evals) != i.RequiredEvaluations() {
		return nil
	}

	poly := make([]F, len(evals))
	for j := range evals {
		eval := &evals[j]
		li := i.LarangePolys[j]
		for k := range poly {
			FE(&poly[k]).Add(&poly[k], FE(new(F)).Multiply(&li[len(li)-k-1], eval))
		}
	}

	return poly
}
