package circuit_abstraction

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	gp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"
)

type ProverData[P any, F any] struct {
	AL []F
	AR []F
	C  []gp.PedersenVectorCommitment[P, F]
	V  []gp.PedersenCommitment[P, F]
}

type Circuit[P any, F any, FE curve.Field[F]] struct {
	Muls int
	// Constraints A series of linear combinations which must evaluate to 0.
	Constraints []gp.LinComb[F, FE]
	Prover      *ProverData[P, F]
}

func CircuitProve[P any, F any, FE curve.Field[F]](
	vectorCommitments []gp.PedersenVectorCommitment[P, F],
	commitments []gp.PedersenCommitment[P, F],
) Circuit[P, F, FE] {
	return Circuit[P, F, FE]{
		Muls:        0,
		Constraints: nil,
		Prover: &ProverData[P, F]{
			C: vectorCommitments,
			V: commitments,
		},
	}
}

func CircuitVerify[P any, F any, FE curve.Field[F]]() Circuit[P, F, FE] {
	return Circuit[P, F, FE]{
		Muls:        0,
		Constraints: nil,
		Prover:      nil,
	}
}

func (c *Circuit[P, F, FE]) Eval(lincomb *gp.LinComb[F, FE]) *F {
	if c.Prover != nil {
		res := lincomb.C
		var tmp F
		for _, e := range lincomb.WL {
			FE(&res).Add(&res, FE(&tmp).Multiply(&c.Prover.AL[e.I], &e.F))
		}
		for _, e := range lincomb.WR {
			FE(&res).Add(&res, FE(&tmp).Multiply(&c.Prover.AR[e.I], &e.F))
		}
		for _, e := range lincomb.WO {
			FE(&res).Add(&res, FE(&tmp).Multiply(FE(&tmp).Multiply(&c.Prover.AL[e.I], &c.Prover.AR[e.I]), &e.F))
		}
		for i, C := range c.Prover.C {
			if WCG, ok := lincomb.WCG.Get(i); ok {
				for _, e := range WCG {
					FE(&res).Add(&res, FE(&tmp).Multiply(&C.GValues[e.I], &e.F))
				}
			}
		}
		for _, e := range lincomb.WV {
			FE(&res).Add(&res, FE(&tmp).Multiply(&c.Prover.V[e.I].Value, &e.F))
		}

		return &res
	}
	return nil
}

func (c *Circuit[P, F, FE]) Multiply(a, b *gp.LinComb[F, FE], witness *[2]F) (gp.Variable, gp.Variable, gp.Variable) {
	l := gp.VariableAL(c.Muls)
	r := gp.VariableAR(c.Muls)
	o := gp.VariableAO(c.Muls)
	c.Muls++

	if c.Prover == nil && witness != nil || c.Prover != nil && witness == nil {
		panic("unreachable")
	}
	if witness != nil {
		c.Prover.AL = append(c.Prover.AL, witness[0])
		c.Prover.AR = append(c.Prover.AR, witness[1])
	}

	if a != nil {
		c.Constraints = append(c.Constraints, *a.Term(FE(new(F)).Negate(FE(new(F)).One()), l))
	}
	if b != nil {
		c.Constraints = append(c.Constraints, *b.Term(FE(new(F)).Negate(FE(new(F)).One()), r))
	}
	return l, r, o
}

func (c *Circuit[P, F, FE]) Statement[PE curve.ExtraCurvePoint[P, F]](
	generators *gp.ProofGenerators[P],
	commitments gp.Commitments[P, F, PE],
) (
	acs *gp.ArithmeticCircuitStatement[P, F, PE, FE],
	acw *gp.ArithmeticCircuitWitness[P, F, FE],
	err error,
) {

	if acs, err = gp.NewArithmeticCircuitStatement(generators, c.Constraints, commitments); err != nil {
		return nil, nil, err
	}

	if c.Prover != nil {
		acw = gp.NewArithmeticCircuitWitness[P, F, FE](c.Prover.AL, c.Prover.AR, c.Prover.C, c.Prover.V)
	}

	return acs, acw, nil
}

// Equality Constrain two linear combinations to be equal.
func (c *Circuit[P, F, FE]) Equality(a, b *gp.LinComb[F, FE]) {
	c.Constraints = append(c.Constraints, *a.Subtract(b))
}

// Inverse Calculate (and constrain) the inverse of a value.
//
// A linear combination may optionally be passed as a constraint for the value being inverted.
// A reference to the inverted value and its inverse is returned.
//
// May panic if any linear combinations reference non-existent terms, the witness isn't provided
// when proving/is provided when verifying, or if the witness is 0 (and accordingly doesn't have
// an inverse).
func (c *Circuit[P, F, FE]) Inverse(lincomb *gp.LinComb[F, FE], witness *F) (gp.Variable, gp.Variable) {
	var witness2 *[2]F
	if witness != nil {
		witness2 = &[2]F{
			*witness,
			*FE(new(F)).Invert(witness),
		}
	}
	l, r, o := c.Multiply(lincomb, nil, witness2)
	// The output of a value multiplied by its inverse is 1
	// Constrain `1 o - 1 = 0`
	c.Constraints = append(c.Constraints, *gp.NewLinCombFrom[F, FE](o).Constant(FE(new(F)).Negate(FE(new(F)).One())))
	return l, r
}

// Inequality Constrain two linear combinations as inequal.
func (c *Circuit[P, F, FE]) Inequality(a, b *gp.LinComb[F, FE], witness2 *[2]F) {
	lConstraint := a.Subtract(b)
	// The existence of a multiplicative inverse means a-b != 0, which means a != b
	var witness *F
	if witness2 != nil {
		witness = FE(new(F)).Subtract(&witness2[0], &witness2[1])
	}

	c.Inverse(lConstraint, witness)
}
