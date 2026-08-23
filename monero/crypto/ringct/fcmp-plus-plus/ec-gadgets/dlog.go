package ec_gadgets

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	circuit_abstraction "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus/circuit-abstraction"
	gb "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"
)

type Parameters struct {
	ScalarBits            int
	XCoefficients         int
	XCoefficientsMinusOne int
	YXCoefficients        int
}

func NewParameters(scalarBits int) (r Parameters) {
	r.ScalarBits = scalarBits
	r.XCoefficients = (r.ScalarBits + 1) / 2
	r.XCoefficientsMinusOne = r.XCoefficients - 1
	r.YXCoefficients = (r.ScalarBits+2)/2 - 2

	return r
}

// GeneratorTable A tabled generator for proving/verifying discrete logarithm claims.
type GeneratorTable[F any] [][2]F

// NewGeneratorTable Create a new table for this generator.
//
// The generator is assumed to be well-formed and on-curve. This function may panic if it's not.
func NewGeneratorTable[F any, FE curve.Field[F]](scalarBits int, curveSpec *CurveSpec[F], generatorX, generatorY *F) (res GeneratorTable[F]) {
	res = make(GeneratorTable[F], scalarBits)
	res[0] = [2]F{*generatorX, *generatorY}
	for i := 1; i < scalarBits; i++ {
		last := &res[i-1]
		curve.WeierstrassAffineDouble[F, FE](&res[i][0], &res[i][1], &curveSpec.A, &last[0], &last[1])
	}
	return res
}

type Divisor struct {
	// Y The coefficient for the `y` term of the divisor.
	//
	// There is never more than one `y**i x**0` coefficient as the leading term of the modulus is
	// `y**2`. It's assumed the coefficient is non-zero (and present) as it will be for any divisor
	// exceeding trivial complexity.
	Y gb.Variable

	// YX The coefficients for the `y**1 x**i` terms of the polynomial.
	YX []gb.Variable

	// XFromPowerOf2 The coefficients for the `x**i` terms of the polynomial, skipping x**1.
	//
	// x**1 is skipped as it's expected to be normalized to 1, and therefore constant, in order to
	// ensure the divisor is non-zero (as necessary for the proof to be complete).
	//
	// Subtract 1 from the length due to skipping the coefficient for x**1
	XFromPowerOf2 []gb.Variable

	// Zero The constant term in the polynomial (alternatively, the coefficient for y**0 x**0).
	Zero gb.Variable
}

type PointWithDlog struct {
	// Point which is supposedly the result of scaling the generator by the discrete logarithm.
	Point [2]gb.Variable
	// Dlog The discrete logarithm, represented as coefficients of a polynomial of 2**i.
	Dlog []gb.Variable
	// Divisor interpolating the relevant doublings of generator with the inverse of the point.
	Divisor Divisor
}

type ChallengePoint[F any] struct {
	Y     F
	YX    []F
	X     []F
	P0N0  F
	XP0N0 []F
	P1N   F
	P1D   F
}

func NewChallengePoint[F any, FE curve.Field[F]](params Parameters, curveSpec *CurveSpec[F], slope *F, x, y *F, invTwoY *F) ChallengePoint[F] {
	// Powers of x, skipping x**0
	xPows := make([]F, params.XCoefficients)
	xPows[0] = *x
	for i := 1; i < params.XCoefficients; i++ {
		last := &xPows[i-1]
		FE(&xPows[i]).Multiply(last, x)
	}

	// Powers of x multiplied by y
	yx := make([]F, params.YXCoefficients)
	// Skips x**0
	FE(&yx[0]).Multiply(y, x)
	for i := 1; i < params.YXCoefficients; i++ {
		last := &yx[i-1]
		FE(&yx[i]).Multiply(last, x)
	}

	var tmp F

	xx := FE(new(F)).Square(x)
	threeXSquared := FE(new(F)).Add(FE(&tmp).Add(xx, xx), xx)
	threeXSquaredPlusA := FE(new(F)).Add(threeXSquared, &curveSpec.A)
	twoY := FE(new(F)).Add(y, y)

	// p_0_n_0 from `DivisorChallenge`
	p0n0 := FE(new(F)).Multiply(threeXSquaredPlusA, invTwoY)
	xp0n0 := make([]F, params.YXCoefficients)
	// Since this iterates over x, which skips x**0, this also skips p_0_n_0 x**0
	for i := range min(params.XCoefficients, params.YXCoefficients) {
		FE(&xp0n0[i]).Multiply(p0n0, &xPows[i])
	}

	// p_1_n from `DivisorChallenge`
	p1n := twoY
	p1d := FE(new(F)).Multiply(FE(&tmp).Negate(slope), p1n)
	FE(p1d).Add(p1d, threeXSquaredPlusA)

	return ChallengePoint[F]{
		Y:     *y,
		YX:    yx,
		X:     xPows,
		P0N0:  *p0n0,
		XP0N0: xp0n0,
		P1N:   *p1n,
		P1D:   *p1d,
	}
}

func DivisorChallengeEval[P any, F any, FE curve.Field[F]](
	circuit *circuit_abstraction.Circuit[P, F, FE],
	divisor *Divisor,
	challenge *ChallengePoint[F],
) gb.Variable {
	// The evaluation of the divisor differentiated by y, further multiplied by p_0_n_0
	// Differentation drops everything without a y coefficient, and drops what remains by a power
	// of y
	// (y**1 -> y**0, yx**i -> x**i)
	// This aligns with p_0_n_1  from `DivisorChallenge`

	var p0n1 gb.LinComb[F, FE]
	{
		p0n1 = *gb.NewEmptyLinComb[F, FE]().Term(&challenge.P0N0, divisor.Y)
		for i := range divisor.YX {
			// This does not index by `j + 1` as x_p_0_n_0 omits x**0
			p0n1.Term(&challenge.XP0N0[i], divisor.YX[i])
		}
	}

	// The evaluation of the divisor differentiated by x
	// This aligns with p_0_n_2  from `DivisorChallenge`
	var p0n2 gb.LinComb[F, FE]
	{
		// The coefficient for x**1 is 1, so 1 becomes the new zero coefficient
		p0n2 = *gb.NewEmptyLinComb[F, FE]().Constant(FE(new(F)).One())

		// Handle the new y coefficient
		p0n2.Term(&challenge.Y, divisor.YX[0])

		// Handle the new yx coefficients
		for i := 1; i < len(divisor.YX); i++ {
			// For the power which was shifted down, we multiply this coefficient
			// 3 x**2 -> 2 * 3 x**1
			originalPowerOfX := curve.ScalarFromUint64[F, FE](new(F), uint64(i)+1)

			// `j - 1` so `j = 1` indexes yx[0] as yx[0] is the y x**1
			// (yx omits y x**0)
			thisWeight := FE(new(F)).Multiply(originalPowerOfX, &challenge.YX[i-1])

			p0n2.Term(thisWeight, divisor.YX[i])
		}

		// Handle the x coefficients
		// We don't skip the first one as `x_from_power_of_2` already omits x**1
		for i := range divisor.XFromPowerOf2 {
			// i + 2 as the paper expects i to start from 1 and be + 1, yet we start from 0
			originalPowerOfX := curve.ScalarFromUint64[F, FE](new(F), uint64(i)+2)

			// Still x[i] as x[0] is x**1
			thisWeight := FE(new(F)).Multiply(originalPowerOfX, &challenge.X[i])
			p0n2.Term(thisWeight, divisor.XFromPowerOf2[i])
		}
	}

	// p_0_n from `DivisorChallenge`
	p0n := p0n1.Add(&p0n2)

	// Evaluation of the divisor
	// p_0_d from `DivisorChallenge`
	var p0d gb.LinComb[F, FE]
	{
		p0d = *gb.NewEmptyLinComb[F, FE]().Term(&challenge.Y, divisor.Y)

		for i := range divisor.YX {
			p0d.Term(&challenge.YX[i], divisor.YX[i])
		}

		for i := range divisor.XFromPowerOf2 {
			// This `i+1` is preserved, despite most not being as x omits x**0, as this assumes we
			// start with `i=1`
			p0d.Term(&challenge.X[i+1], divisor.XFromPowerOf2[i])
		}

		// Adding x effectively adds a `1 x` term, ensuring the divisor isn't 0
		p0d.Term(FE(new(F)).One(), divisor.Zero).Constant(&challenge.X[0])
	}

	// Calculate the joint numerator
	// p_n from `DivisorChallenge`
	pn := p0n.Multiply(&challenge.P1N)
	// Calculate the joint denominator
	// p_d from `DivisorChallenge`
	pd := p0d.Multiply(&challenge.P1D)

	// We want `n / d = o`
	// `n / d = o` == `n = d * o`
	witness := circuit.Eval(pd)
	var witness2 *[2]F
	if witness != nil {
		witness2 = &[2]F{*witness, *FE(new(F)).Multiply(circuit.Eval(pn), FE(new(F)).Invert(witness))}
	}
	_, o, nClaim := circuit.Multiply(pd, nil, witness2)
	circuit.Equality(pn, gb.NewLinCombFrom[F, FE](nClaim))

	return o
}

// DiscreteLogChallenge A challenge to evaluate divisors with.
//
// This challenge must be sampled after writing the commitments to the transcript. This challenge
// is reusable across various divisors.
type DiscreteLogChallenge[F any] struct {
	C0 ChallengePoint[F]
	C1 ChallengePoint[F]
	C2 ChallengePoint[F]

	Slope     F
	Intercept F
}

// ChallengedGenerator A generator which has been challenged and is ready for use in evaluating discrete logarithm claims.
type ChallengedGenerator[F any] []F

type EcDlogGadgets[F any] interface {
	// DiscreteLogChallenge Sample a challenge for a series of discrete logarithm claims.
	//
	// This must be called after writing the commitments to the transcript.
	//
	// The generators are assumed to be non-empty. They are not transcripted. If your generators are
	// dynamic, they must be properly transcripted into the context.
	//
	// May panic/have undefined behavior if an assumption is broken.
	DiscreteLogChallenge(transcript circuit_abstraction.Transcript[F], curveSpec *CurveSpec[F], generators GeneratorTable[F]) (DiscreteLogChallenge[F], []ChallengedGenerator[F])

	// DiscreteLog Prove this point has the specified discrete logarithm over the specified generator.
	//
	// The discrete logarithm is not validated to be in a canonical form. The only guarantee made on
	// it is that it's a consistent representation of _a_ discrete logarithm (reuse won't enable
	// re-interpretation as a distinct discrete logarithm).
	//
	// This does ensure the point is on-curve.
	//
	// This MUST only be called with `Variable`s present within commitments.
	//
	// May panic/have undefined behavior if an assumption is broken, or if passed an invalid
	// witness.
	DiscreteLog(curveSpec *CurveSpec[F], point PointWithDlog, challenge *DiscreteLogChallenge[F], challengedGenerator *ChallengedGenerator[F]) OnCurve
}
