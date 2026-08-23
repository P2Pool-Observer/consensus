package fcmp_plus_plus

import (
	"crypto/subtle"
	"reflect"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	circuit_abstraction "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus/circuit-abstraction"
	ec_gadgets "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus/ec-gadgets"
	gp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type Circuit[P any, F any, FE curve.ExtraField[F]] struct {
	circuit_abstraction.Circuit[P, F, FE]
}

func (c *Circuit[P, F, FE]) FirstLayer(
	params ec_gadgets.Parameters,
	transcript circuit_abstraction.Transcript[F],
	curveSpec *ec_gadgets.CurveSpec[F],

	TTable ec_gadgets.GeneratorTable[F],
	UTable ec_gadgets.GeneratorTable[F],
	VTable ec_gadgets.GeneratorTable[F],
	GTable ec_gadgets.GeneratorTable[F],

	OTilde [2]F,
	OBlind *ec_gadgets.PointWithDlog,
	O [2]gp.Variable,

	ITilde [2]F,
	IBlindU *ec_gadgets.PointWithDlog,
	I [2]gp.Variable,

	R [2]F,
	IBlindV *ec_gadgets.PointWithDlog,
	IBlindBlind *ec_gadgets.PointWithDlog,

	CTilde [2]F,
	CBlind *ec_gadgets.PointWithDlog,
	C [2]gp.Variable,

	branch [][]gp.Variable,
) {

	challenge, challengeGenerators := c.DiscreteLogChallenge(params, transcript, curveSpec, []ec_gadgets.GeneratorTable[F]{TTable, UTable, VTable, GTable})
	challengedT := challengeGenerators[0]
	challengedU := challengeGenerators[1]
	challengedV := challengeGenerators[2]
	challengedG := challengeGenerators[3]

	{
		O := c.OnCurve(curveSpec, O)
		OBlind := c.DiscreteLog(curveSpec, OBlind, &challenge, challengedT)
		c.IncompleteAddFixed(OTilde, OBlind, O)

		// This cannot simply be removed in order to cheat this proof
		// The discrete logarithms we assert equal are actually asserting the variables we use to refer
		// to the discrete logarithms are equal
		// If a dishonest prover removes this assertion and passes two different sets of variables,
		// they'll generate a different circuit
		// An honest verifier will generate the intended circuit (using a consistent set of variables)
		// and still reject such proofs
		// This check only exists for sanity/safety to ensure an honest verifier doesn't mis-call this
		//
		// TODO: remove reflect usage
		if !reflect.DeepEqual(IBlindU.Dlog, IBlindV.Dlog) {
			panic("first layer passed differing variables for the dlog")
		}

		I := c.OnCurve(curveSpec, I)
		IBlindU := c.DiscreteLog(curveSpec, IBlindU, &challenge, challengedU)
		c.IncompleteAddFixed(ITilde, IBlindU, I)

		IBlindV := c.DiscreteLog(curveSpec, IBlindV, &challenge, challengedV)
		IBlindBlind := c.DiscreteLog(curveSpec, IBlindBlind, &challenge, challengedT)
		c.IncompleteAddFixed(R, IBlindV, IBlindBlind)

		C := c.OnCurve(curveSpec, C)
		CBlind := c.DiscreteLog(curveSpec, CBlind, &challenge, challengedG)
		c.IncompleteAddFixed(CTilde, CBlind, C)

		c.TupleMemberOfList(transcript, []gp.Variable{O.X, O.Y, I.X, I.Y, C.X, C.Y}, branch)
	}
}

func (c *Circuit[P, F, FE]) AdditionalLayerDiscreteLogChallenge(params ec_gadgets.Parameters, transcript circuit_abstraction.Transcript[F], curveSpec *ec_gadgets.CurveSpec[F], HTable ec_gadgets.GeneratorTable[F]) (ec_gadgets.DiscreteLogChallenge[F], ec_gadgets.ChallengedGenerator[F]) {
	challenge, challengedGenerator := c.DiscreteLogChallenge(params, transcript, curveSpec, []ec_gadgets.GeneratorTable[F]{HTable})
	return challenge, challengedGenerator[0]
}

func (c *Circuit[P, F, FE]) AdditionalLayer(
	curveSpec *ec_gadgets.CurveSpec[F],
	challenge ec_gadgets.DiscreteLogChallenge[F],
	challengedGenerator ec_gadgets.ChallengedGenerator[F],
	blindedHash [2]F,
	blind *ec_gadgets.PointWithDlog,
	hash [2]gp.Variable,
	branch []gp.Variable,
) {
	{
		blind := c.DiscreteLog(curveSpec, blind, &challenge, challengedGenerator)
		hash := c.OnCurve(curveSpec, hash)
		c.IncompleteAddFixed(blindedHash, blind, hash)
		branchComb := make([]gp.LinComb[F, FE], 0, len(branch))
		for i := range branch {
			branchComb = append(branchComb, *gp.NewLinCombFrom[F, FE](branch[i]))
		}
		c.MemberOfList(*gp.NewLinCombFrom[F, FE](hash.X), branchComb)
	}
}

func sampleEmbeddedCurvePoint[F any, FE curve.ExtraField[F]](transcript circuit_abstraction.Transcript[F], curveSpec *ec_gadgets.CurveSpec[F], oddYCoordinate int) (x, y F) {
	var cx, cy F
	for {
		transcript.Challenge(&cx)
		FE(&cy).Multiply(FE(new(F)).Square(&cx), &cx)
		FE(&cy).Add(&cy, FE(new(F)).Multiply(&curveSpec.A, &cx))
		FE(&cy).Add(&cy, &curveSpec.B)
		if FE(&cy).Sqrt(&cy) == nil {
			continue
		}

		// Takes a specific y coordinate as to not be dependent on whatever root the above sqrt happens to returns
		FE(&cy).Select(&cy, FE(new(F)).Negate(&cy), subtle.ConstantTimeEq(int32(FE(&cy).IsNegative()), int32(oddYCoordinate)))

		return cx, cy
	}
}

func (c *Circuit[P, F, FE]) DiscreteLogChallenge(params ec_gadgets.Parameters, transcript circuit_abstraction.Transcript[F], curveSpec *ec_gadgets.CurveSpec[F], generators []ec_gadgets.GeneratorTable[F]) (ec_gadgets.DiscreteLogChallenge[F], []ec_gadgets.ChallengedGenerator[F]) {
	// Get the challenge points
	signOfPoints := transcript.ChallengeBytes()
	signOfPoint0 := int(signOfPoints[0] & 1)
	signOfPoint1 := int((signOfPoints[0] >> 1) & 1)

	c0x, c0y := sampleEmbeddedCurvePoint[F, FE](transcript, curveSpec, signOfPoint0)
	c1x, c1y := sampleEmbeddedCurvePoint[F, FE](transcript, curveSpec, signOfPoint1)

	c2x, c2y := curve.WeierstrassAffineIncompleteAdd[F, FE](new(F), new(F), &c0x, &c0y, &c1x, &c1y)
	// We want C0, C1, C2 = -(C0 + C1)
	FE(c2y).Negate(c2y)

	// Calculate the slope and intercept
	// Safe invert as these x coordinates must be distinct due to passing the above incomplete_add
	slope := FE(new(F)).Multiply(FE(new(F)).Subtract(&c1y, &c0y), FE(new(F)).Subtract(&c1x, &c0x))
	if FE(slope).Invert(slope) == nil {
		panic("slope is nil")
	}
	intercept := FE(new(F)).Subtract(&c0y, FE(new(F)).Multiply(slope, &c0x))

	// Calculate the inversions for 2 c_y (for each c) and all of the challenged generators
	inversions := make([]F, 3+(len(generators)*params.ScalarBits))

	// Needed for the left-hand side eval
	FE(&inversions[0]).Add(&c0y, &c0y)
	FE(&inversions[1]).Add(&c1y, &c1y)
	FE(&inversions[2]).Add(c2y, c2y)

	// Perform the inversions for the generators
	for i := range generators {
		// Needed for the right-hand side eval
		for j := range generators[i] {
			// `DiscreteLog` has weights of `(mu - (G_i.y + (slope * G_i.x)))**-1` in its last line
			inversions[3+(i*params.ScalarBits)+j] = *FE(new(F)).Subtract(intercept, FE(new(F)).Subtract(&generators[i][j][1], FE(new(F)).Multiply(slope, &generators[i][j][0])))
		}
	}
	for i := range inversions {
		if FE(&inversions[i]).IsZero() == 1 {
			// This should be unreachable barring negligible probability
			panic("trying to invert 0")
		}
	}

	curve.BatchInvert[F, FE](new(F), utils.ValuesToPointers(inversions)...)

	var j int

	invC0TwoY := inversions[0]
	invC1TwoY := inversions[1]
	invC2TwoY := inversions[2]

	j = 3

	c0 := ec_gadgets.NewChallengePoint[F, FE](params, curveSpec, slope, &c0x, &c0y, &invC0TwoY)
	c1 := ec_gadgets.NewChallengePoint[F, FE](params, curveSpec, slope, &c1x, &c1y, &invC1TwoY)
	c2 := ec_gadgets.NewChallengePoint[F, FE](params, curveSpec, slope, c2x, c2y, &invC2TwoY)

	// Fill in the inverted values
	challengedGenerators := make([]ec_gadgets.ChallengedGenerator[F], 0, len(generators))
	for range generators {
		challengedGenerator := make(ec_gadgets.ChallengedGenerator[F], params.ScalarBits)
		for i := range params.ScalarBits {
			challengedGenerator[i] = inversions[j]
			j++
		}
		challengedGenerators = append(challengedGenerators, challengedGenerator)
	}

	return ec_gadgets.DiscreteLogChallenge[F]{
		C0:        c0,
		C1:        c1,
		C2:        c2,
		Slope:     *slope,
		Intercept: *intercept,
	}, challengedGenerators
}

func (c *Circuit[P, F, FE]) DiscreteLog(curveSpec *ec_gadgets.CurveSpec[F], dlogPoint *ec_gadgets.PointWithDlog, challenge *ec_gadgets.DiscreteLogChallenge[F], challengedGenerator ec_gadgets.ChallengedGenerator[F]) ec_gadgets.OnCurve {
	//TODO: check variables are CG or V "discrete log proofs requires all arguments belong to commitments"

	// Check the point is on curve
	point := c.OnCurve(curveSpec, dlogPoint.Point)

	// The challenge has already been sampled so those lines aren't necessary

	// lhs from the paper, evaluating the divisor
	lhsEval := gp.NewLinCombFrom[F, FE](ec_gadgets.DivisorChallengeEval(&c.Circuit, &dlogPoint.Divisor, &challenge.C0))
	lhsEval.Add(gp.NewLinCombFrom[F, FE](ec_gadgets.DivisorChallengeEval(&c.Circuit, &dlogPoint.Divisor, &challenge.C1)))
	lhsEval.Add(gp.NewLinCombFrom[F, FE](ec_gadgets.DivisorChallengeEval(&c.Circuit, &dlogPoint.Divisor, &challenge.C2)))

	// Interpolate the doublings of the generator
	rhsEval := gp.NewEmptyLinComb[F, FE]()
	// We call this `bit` yet it's not constrained to being a bit
	// It's presumed to be yet may be malleated
	for i := range dlogPoint.Dlog {
		rhsEval.Term(&challengedGenerator[i], dlogPoint.Dlog[i])
	}

	// Interpolate the output point
	// intercept - (y - (slope * x))
	// intercept - y + (slope * x)
	// -y + (slope * x) + intercept
	// EXCEPT the output point we're proving the discrete log for isn't the one interpolated
	// Its negative is, so -y becomes positive
	// y + (slope * x) + intercept
	outputInterpolation := gp.NewEmptyLinComb[F, FE]().Constant(&challenge.Intercept).
		Term(FE(new(F)).One(), point.Y).
		Term(&challenge.Slope, point.X)

	outputInterpolationEval := c.Eval(outputInterpolation)
	_, inverse := c.Inverse(outputInterpolation, outputInterpolationEval)
	rhsEval.Term(FE(new(F)).One(), inverse)

	c.Equality(lhsEval, rhsEval)

	return point
}

func (c *Circuit[P, F, FE]) TupleMemberOfList(transcript circuit_abstraction.Transcript[F], member []gp.Variable, list [][]gp.Variable) {

	// check all variables are CG
	{
		for _, v := range member {
			if _, ok := v.(gp.VariableCG); !ok {
				panic("unsupported")
			}
		}
		for _, vv := range list {
			for _, v := range vv {
				if _, ok := v.(gp.VariableCG); !ok {
					panic("unsupported")
				}
			}
		}
	}

	// Create challenges which we use to aggregate tuples into LinCombs
	challenges := make([]F, 0, len(member))
	for range member {
		challenges = append(challenges, *transcript.Challenge(new(F)))
	}

	// Aggregate the claimed member
	var memberLinComb gp.LinComb[F, FE]
	{
		memberLinComb = *gp.NewEmptyLinComb[F, FE]()
		for i, m := range member {
			memberLinComb.Add(gp.NewLinCombFrom[F, FE](m).Multiply(&challenges[i]))
		}
	}

	// Aggregate the list members
	var listLinComb []gp.LinComb[F, FE]
	{
		for _, l := range list {
			res := gp.NewEmptyLinComb[F, FE]()
			for i, m := range l {
				res.Add(gp.NewLinCombFrom[F, FE](m).Multiply(&challenges[i]))
			}
			listLinComb = append(listLinComb, *res)
		}
	}

	c.MemberOfList(memberLinComb, listLinComb)
}

func (c *Circuit[P, F, FE]) MemberOfList(member gp.LinComb[F, FE], list []gp.LinComb[F, FE]) {
	// Initialize the carry to the first list member minus the claimed member
	carry := &list[0]
	list = list[1:]
	carry.Subtract(&member)

	for _, m := range list {
		// Multiply the carry by the next evaluation
		next := m.Subtract(&member)
		carryEval := c.Eval(carry)
		nextEval := c.Eval(next)
		var witness2 *[2]F
		if carryEval != nil {
			witness2 = &[2]F{*carryEval, *nextEval}
		}
		_, _, constrainableCarry := c.Multiply(carry, next, witness2)
		carry = gp.NewLinCombFrom[F, FE](constrainableCarry)
	}

	c.Constraints = append(c.Constraints, *carry)
}

func (c *Circuit[P, F, FE]) OnCurve(curve *ec_gadgets.CurveSpec[F], point [2]gp.Variable) ec_gadgets.OnCurve {
	x, y := point[0], point[1]
	xEval := c.Eval(gp.NewLinCombFrom[F, FE](x))
	var witness2 *[2]F
	if xEval != nil {
		witness2 = &[2]F{*xEval, *xEval}
	}
	_, _, x2 := c.Multiply(gp.NewLinCombFrom[F, FE](x), gp.NewLinCombFrom[F, FE](x), witness2)

	if xEval != nil {
		witness2 = &[2]F{*FE(new(F)).Multiply(xEval, xEval), *xEval}
	} else {
		witness2 = nil
	}
	_, _, x3 := c.Multiply(gp.NewLinCombFrom[F, FE](x2), gp.NewLinCombFrom[F, FE](x), witness2)
	expected_y2 := gp.NewLinCombFrom[F, FE](x3).Term(&curve.A, x).Constant(&curve.B)

	yEval := c.Eval(gp.NewLinCombFrom[F, FE](y))
	if yEval != nil {
		witness2 = &[2]F{*yEval, *yEval}
	} else {
		witness2 = nil
	}
	_, _, y2 := c.Multiply(gp.NewLinCombFrom[F, FE](y), gp.NewLinCombFrom[F, FE](y), witness2)

	c.Equality(gp.NewLinCombFrom[F, FE](y2), expected_y2)

	return ec_gadgets.OnCurve{X: x, Y: y}
}

func (c *Circuit[P, F, FE]) IncompleteAddFixed(a [2]F, b, c_ ec_gadgets.OnCurve) ec_gadgets.OnCurve {
	// Check b.x != a.0
	{
		bx_lincomb := gp.NewLinCombFrom[F, FE](b.X)
		bx_eval := c.Eval(bx_lincomb)
		var witness2 *[2]F
		if bx_eval != nil {
			witness2 = &[2]F{*bx_eval, a[0]}
		}
		c.Inequality(bx_lincomb, gp.NewEmptyLinComb[F, FE]().Constant(&a[0]), witness2)
	}

	x0, y0 := a[0], a[1]
	x1, y1 := b.X, b.Y
	x2, y2 := c_.X, c_.Y

	var slope_eval *F
	if x1 := c.Eval(gp.NewLinCombFrom[F, FE](x1)); x1 != nil {
		y1 := c.Eval(gp.NewLinCombFrom[F, FE](b.Y))
		slope_eval = FE(new(F)).Multiply(FE(new(F)).Subtract(y1, &y0), FE(new(F)).Subtract(x1, &x0))
		slope_eval = FE(slope_eval).Invert(slope_eval)
	}

	// slope * (x1 - x0) = y1 - y0
	x1_minus_x0 := gp.NewLinCombFrom[F, FE](x1).Constant(FE(new(F)).Negate(&x0))
	x1_minus_x0_eval := c.Eval(x1_minus_x0)

	var witness2 *[2]F
	if slope_eval != nil {
		witness2 = &[2]F{*slope_eval, *x1_minus_x0_eval}
	}
	slope, _, o := c.Multiply(nil, x1_minus_x0, witness2)
	c.Equality(gp.NewLinCombFrom[F, FE](o), gp.NewLinCombFrom[F, FE](y1).Constant(FE(new(F)).Negate(&y0)))

	// slope * (x2 - x0) = -y2 - y0
	x2_minus_x0 := gp.NewLinCombFrom[F, FE](x2).Constant(FE(new(F)).Negate(&x0))
	x2_minus_x0_eval := c.Eval(x2_minus_x0)
	if slope_eval != nil {
		witness2 = &[2]F{*slope_eval, *x2_minus_x0_eval}
	} else {
		witness2 = nil
	}
	_, _, o = c.Multiply(gp.NewLinCombFrom[F, FE](slope), x2_minus_x0, witness2)
	c.Equality(gp.NewLinCombFrom[F, FE](o), gp.NewEmptyLinComb[F, FE]().Term(FE(new(F)).Negate(FE(new(F)).One()), y2).Constant(FE(new(F)).Negate(&y0)))

	// slope * slope = x0 + x1 + x2
	if slope_eval != nil {
		witness2 = &[2]F{*slope_eval, *slope_eval}
	} else {
		witness2 = nil
	}
	_, _, o = c.Multiply(gp.NewLinCombFrom[F, FE](slope), gp.NewLinCombFrom[F, FE](slope), witness2)
	c.Equality(gp.NewLinCombFrom[F, FE](o), gp.NewLinCombFrom[F, FE](x1).Term(FE(new(F)).One(), x2).Constant(&x0))

	return ec_gadgets.OnCurve{X: x2, Y: y2}
}
