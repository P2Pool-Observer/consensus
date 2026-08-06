package generalized_bulletproofs

import (
	"errors"
	"io"
	"math"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
)

type ArithmeticCircuitWitness[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.BasicField[F]] struct {
	AL ScalarVector[F, FE]
	AR ScalarVector[F, FE]
	AO ScalarVector[F, FE]

	C []PedersenVectorCommitment[P, F, PE, FE]
	V []PedersenCommitment[P, F, PE, FE]
}

func (acw *ArithmeticCircuitWitness[P, F, PE, FE]) VMaskVec() (ret ScalarVector[F, FE]) {
	ret = make(ScalarVector[F, FE], 0, len(acw.V))
	for _, v := range acw.V {
		ret = append(ret, v.Mask)
	}
	return ret
}

func NewArithmeticCircuitWitness[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.BasicField[F]](
	aL, aR []F,
	c []PedersenVectorCommitment[P, F, PE, FE],
	v []PedersenCommitment[P, F, PE, FE],
) *ArithmeticCircuitWitness[P, F, PE, FE] {
	if len(aL) != len(aR) {
		return nil
	}

	// If no IPA rows were used, pad to have a length of one
	// This proof may be pointless, but it'll prove
	if len(aL) == 0 {
		aL = []F{*FE(new(F)).Zero()}
		aR = []F{*FE(new(F)).Zero()}
	}

	ao := slices.Clone(ScalarVector[F, FE](aL)).MultiplyVec(aR)
	return &ArithmeticCircuitWitness[P, F, PE, FE]{
		AL: aL,
		AR: aR,
		AO: ao,
		C:  c,
		V:  v,
	}
}

type ArithmeticCircuitStatement[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]] struct {
	Generators  ProofGenerators[P]
	Constraints []LinComb[F, FE]

	C PointVector[P, F, PE, FE]
	V PointVector[P, F, PE, FE]
}

func NewArithmeticCircuitStatement[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]](
	generators *ProofGenerators[P],
	constraints []LinComb[F, FE],
	commitments Commitments[P, F, PE, FE],
) (*ArithmeticCircuitStatement[P, F, PE, FE], error) {
	for _, constraint := range constraints {
		if len(generators.GBold) <= constraint.HighestAIndex {
			return nil, errors.New("constraint referred to non existent term")
		}
		if len(commitments.C) <= constraint.HighestCIndex {
			return nil, errors.New("constraint referred to non existent vector commitment")
		}
		if len(commitments.V) <= constraint.HighestVIndex {
			return nil, errors.New("constraint referred to non existent commitment")
		}
	}

	// This ensures we may perform `n' = 2 * n_c + 2, 2 * (n' + 1)` with plenty of room,
	// without limiting any realistic uses of this proof
	if len(commitments.C) >= (math.MaxInt >> 4) {
		return nil, errors.New("too many commitments")
	}

	return &ArithmeticCircuitStatement[P, F, PE, FE]{
		Generators:  *generators,
		Constraints: constraints,
		C:           commitments.C,
		V:           commitments.V,
	}, nil
}

func (acs *ArithmeticCircuitStatement[P, F, PE, FE]) NumN() int {
	return len(acs.Generators.GBold)
}

func (acs *ArithmeticCircuitStatement[P, F, PE, FE]) NumQ() int {
	return len(acs.Constraints)
}

func (acs *ArithmeticCircuitStatement[P, F, PE, FE]) NumC() int {
	return len(acs.C)
}

func (acs *ArithmeticCircuitStatement[P, F, PE, FE]) NumM() int {
	return len(acs.V)
}

type YzChallenges[F any, FE curve.BasicField[F]] struct {
	YInv ScalarVector[F, FE]
	Z    ScalarVector[F, FE]
}

func (acs *ArithmeticCircuitStatement[P, F, PE, FE]) YZChallenges(y, z1 *F) YzChallenges[F, FE] {
	yInv := ScalarPowers[F, FE](FE(new(F)).Invert(y), acs.NumN())

	// Powers of z *starting with z**1*
	// We could reuse powers and remove the first element, yet this is cheaper than the shift that
	// would require

	q := acs.NumQ()
	z := make(ScalarVector[F, FE], 0, q)
	z = append(z, *z1)
	for range q - 1 {
		z = append(z, *FE(new(F)).Multiply(&z[len(z)-1], z1))
	}
	z = z[:q]

	return YzChallenges[F, FE]{
		YInv: yInv,
		Z:    z,
	}
}

// Prove for this statement/witness.
//
// This is only guaranteed to return a valid proof when the witness satisfies the statement. It
// may or may not return an error if the witness does not satisfy the statement.
func (acs *ArithmeticCircuitStatement[P, F, PE, FE]) Prove(
	transcript *Transcript[P, F, PE, FE],
	witness *ArithmeticCircuitWitness[P, F, PE, FE],
	randomReader io.Reader,
) error {
	n := acs.NumN()
	c := acs.NumC()
	m := acs.NumM()

	// Check the witness length
	if len(witness.AL) > n {
		return ErrIncorrectAmountOfGenerators
	}
	for _, c := range witness.C {
		if len(c.GValues) > n {
			return ErrIncorrectAmountOfGenerators
		}
	}

	// Check the witness's consistency with the statement
	if c != len(witness.C) || m != len(witness.V) {
		return ErrInconsistentWitness
	}

	if debugChecks {
		_ = acs
		//TODO
	}

	alpha := curve.RandomField[F, FE](new(F), randomReader)
	beta := curve.RandomField[F, FE](new(F), randomReader)
	rho := curve.RandomField[F, FE](new(F), randomReader)

	type PointPair = multiexp.ScalarPointPair[P, F, PE, FE]

	var AI, AO P
	{
		var AITerms []PointPair
		for i := range witness.AL {
			AITerms = append(AITerms, PointPair{S: witness.AL[i], P: acs.Generators.GBold[i]})
		}
		for i := range witness.AR {
			AITerms = append(AITerms, PointPair{S: witness.AR[i], P: acs.Generators.HBold[i]})
		}
		AITerms = append(AITerms, PointPair{S: *alpha, P: acs.Generators.H})

		multiexp.MultiExp[P, F, PE, FE](&AI, AITerms)
	}
	{
		var AOTerms []PointPair
		for i := range witness.AO {
			AOTerms = append(AOTerms, PointPair{S: witness.AO[i], P: acs.Generators.GBold[i]})
		}
		AOTerms = append(AOTerms, PointPair{S: *beta, P: acs.Generators.H})

		multiexp.MultiExp[P, F, PE, FE](&AO, AOTerms)
	}

	sL := make(ScalarVector[F, FE], n)
	sR := make(ScalarVector[F, FE], n)
	for i := range n {
		curve.RandomScalar[F, FE](&sL[i], randomReader)
		curve.RandomScalar[F, FE](&sR[i], randomReader)
	}
	var S P
	{
		var STerms []PointPair
		for i := range sL {
			STerms = append(STerms, PointPair{S: sL[i], P: acs.Generators.GBold[i]})
		}
		for i := range sR {
			STerms = append(STerms, PointPair{S: sR[i], P: acs.Generators.HBold[i]})
		}
		STerms = append(STerms, PointPair{S: *rho, P: acs.Generators.H})

		multiexp.MultiExp[P, F, PE, FE](&S, STerms)
	}

	transcript.PushPoint(&AI)
	transcript.PushPoint(&AO)
	transcript.PushPoint(&S)

	y := transcript.Challenge(new(F))
	z := transcript.Challenge(new(F))
	yz := acs.YZChallenges(y, z)
	yPowers := ScalarPowers[F, FE](y, n)

	/*
	   `t` is a degree-`2 * (n' + 1)` polynomial.

	   While Bulletproofs defines and considers it as a degree-6 polynomial, this re-definition is
	   part of the expanded statement offered by Generalized Bulletproofs such that
	   `n' = (2 * c) + 2`. When `c`, the amount of vector commitments, is `0`, we have `n' = 2`,
	   and `t = 2 * (2 + 1) = 6`, collapsing the structure of `t` back to the definition within the
	   original Bulletproofs paper.
	*/

	ni := (2 * c) + 2
	// These indexes are from the Generalized Bulletproofs (fixed) paper
	ilr := ni / 2
	io := ni
	is := ni + 1
	jlr := ilr
	jo := 0
	js := is

	// Declare the l and r polynomials, assigning the traditional coefficients to their positions
	l := make([]ScalarVector[F, FE], is+1)
	r := make([]ScalarVector[F, FE], is+1)

	var lWeights, rWeights, oWeights ScalarVector[F, FE]
	{
		lWeights = make(ScalarVector[F, FE], n)
		rWeights = make(ScalarVector[F, FE], n)
		oWeights = make(ScalarVector[F, FE], n)
		/*
		   Track the index of the highest element within this vector actually used.

		   This allows us to truncate it after, saving operations over values we know will be zero.
		*/
		var lHi, rHi, oHi int
		for i := range acs.Constraints {
			lHi = max(lHi, AccumulateVector(lWeights, acs.Constraints[i].WL, &yz.Z[i]))
			rHi = max(rHi, AccumulateVector(rWeights, acs.Constraints[i].WR, &yz.Z[i]))
			oHi = max(oHi, AccumulateVector(oWeights, acs.Constraints[i].WO, &yz.Z[i]))
		}

		// Perform the truncation, and as `*_hi` represents the index, add `1` to obtain the length
		// we're truncating to (preserving all values we did actually write to)
		lWeights = lWeights[:lHi+1]
		rWeights = rWeights[:rHi+1]
		oWeights = oWeights[:oHi+1]
	}

	l[ilr] = rWeights
	l[ilr].MultiplyVec(yz.YInv)
	l[ilr].AddVecUnchecked(witness.AL)

	// If the prior while loop terminated because `l[ilr]` was short, push the rest of `aL`
	if len(l[ilr]) < len(witness.AL) {
		l[ilr] = append(l[ilr], witness.AL[len(l[ilr]):]...)
	}

	l[io] = slices.Clone(witness.AO)
	l[is] = sL

	r[jlr] = lWeights
	r[jlr] = slices.Grow(r[jlr], len(r[jlr])+len(witness.AR))
	aRy := slices.Clone(witness.AR).MultiplyVec(yPowers)
	r[jlr].AddVecUnchecked(aRy)
	// If the prior while loop terminated because `r[jlr]` was short, push the rest of `aR_y`
	if len(r[jlr]) < len(aRy) {
		r[jlr] = append(r[jlr], aRy[len(r[jlr]):]...)
	}

	r[jo] = oWeights.SubtractVec(yPowers)
	// As the prior loop may terminate if `o_weights` was short, push the rest of `r[jo]` (`-y`)
	for i := len(oWeights); i < n; i++ {
		r[jo] = append(r[jo], *FE(new(F)).Negate(&yPowers[i]))
	}

	r[js] = sR.MultiplyVec(yPowers)

	/*
	   We now fill in the vector commitments.

	   We use unused coefficients of `l` increasing from `0` (skipping `ilr`), and unused
	   coefficients of `r` decreasing from `ni` (skipping `jlr`).
	*/

	for i, c := range witness.C {
		var cgWeights ScalarVector[F, FE]
		{
			cg := make(ScalarVector[F, FE], n)
			var cgHi int
			for j := range acs.Constraints {
				if WCG, ok := acs.Constraints[j].WCG.Get(i); ok {
					cgHi = max(cgHi, AccumulateVector(cg, WCG, &yz.Z[j]))
				}
			}

			cg = cg[:cgHi+1]

			cgWeights = cg
		}

		{
			i := 1 + i
			j := ni - i

			l[j] = slices.Clone(c.GValues)
			r[i] = cgWeights
			// This does not set `r[j]` as our prover does not populate the right-hand of the VCs
		}
	}

	// Multiply `l` and `r` to obtain `t`
	t := make(ScalarVector[F, FE], 1+(2*(len(l)-1)))
	for i, l := range l {
		if i < (ni / 2) {
			// This is guaranteed due to how these elements of `l` aren't populated by the indexing
			if debugChecks {
				for _, coeff := range l {
					if FE(&coeff).IsZero() == 0 {
						panic("unreachable")
					}
				}
			}
			continue
		}
		for j, r := range r {
			ip := l.InnerProductUnchecked(r)
			FE(&t[i+j]).Add(&t[i+j], &ip)
		}
	}

	/*
	   Per Bulletproofs, calculate masks `tau` for each element of `t` where `(i > 0) && (i != 2)`.
	   Per Generalized Bulletproofs, calculate masks `tau` for each `t` where `i != n'`.
	   With Bulletproofs, `t[0]` is zero, hence its omission, yet Generalized Bulletproofs uses it.
	   Then, `n'` is equal to `2` when no vector commitments are present.
	*/
	var tauBeforeNi, tauAfterNi []F
	for i := ni / 2; i < ni; i++ {
		tauBeforeNi = append(tauBeforeNi, *curve.RandomScalar[F, FE](new(F), randomReader))
	}
	for range t[(ni + 1):] {
		tauAfterNi = append(tauAfterNi, *curve.RandomScalar[F, FE](new(F), randomReader))
	}

	// Calculate commitments to the coefficients of `t`, blinded by `tau`
	for i, t := range t[ni/2 : ni] {
		transcript.PushPoint(PE(new(P)).DoubleScalarMult(&t, &acs.Generators.G, &tauBeforeNi[i], &acs.Generators.H))
	}
	for i, t := range t[ni+1:] {
		transcript.PushPoint(PE(new(P)).DoubleScalarMult(&t, &acs.Generators.G, &tauAfterNi[i], &acs.Generators.H))
	}
	x := ScalarPowers[F, FE](transcript.Challenge(new(F)), len(t))

	polyEval := func(poly []ScalarVector[F, FE], x ScalarVector[F, FE]) (res ScalarVector[F, FE]) {
		res = make(ScalarVector[F, FE], n)
		for i := range poly {
			for j := range min(len(res), len(poly[i])) {
				FE(&res[j]).Add(&res[j], FE(new(F)).Multiply(&poly[i][j], &x[i]))
			}
		}
		return res
	}

	{
		l := polyEval(l, x)
		r := polyEval(r, x)

		tCaret := slices.Clone(l).InnerProduct(r)

		VWeights := make(ScalarVector[F, FE], len(acs.V))
		for i := range acs.Constraints {
			// We use `-z`, not `z`, as we write our constraint as `... + WV V = 0` not `= WV V + ..`
			// This means we need to subtract `WV V` from both sides, which we accomplish here
			AccumulateVector(VWeights, acs.Constraints[i].WV, FE(new(F)).Negate(&yz.Z[i]))
		}

		var tauX, mu F
		{
			tauXPoly := make([]F, 0, len(t)-(ni/2))
			tauXPoly = append(tauXPoly, tauBeforeNi...)
			tauXPoly = append(tauXPoly, VWeights.InnerProduct(witness.VMaskVec()))
			tauXPoly = append(tauXPoly, tauAfterNi...)

			FE(&tauX).Zero()
			for i, coeff := range tauXPoly {
				FE(&tauX).Add(&tauX, FE(new(F)).Multiply(&coeff, &x[(ni/2)+i]))
			}
		}

		// Calculate `mu` for the powers of `x` variable to `ilr`/`io`/`is`
		{
			// Calculate the first part of `mu`
			FE(&mu).Multiply(alpha, &x[ilr])
			FE(&mu).Add(&mu, FE(new(F)).Multiply(beta, &x[io]))
			FE(&mu).Add(&mu, FE(new(F)).Multiply(rho, &x[is]))

			// Incorporate the commitment masks multiplied by the associated power of `x`
			for i, commitment := range witness.C {
				FE(&mu).Add(&mu, FE(new(F)).Multiply(&x[ni-(1+i)], &commitment.Mask))
			}
		}

		transcript.PushScalar(&tauX)
		transcript.PushScalar(&mu)
		transcript.PushScalar(&tCaret)

		/*
		   Use the Inner-Product argument to prove for the following statement:
		     `P = l * g_bold + r * (y_inv * h_bold), t_caret = <l, r>`
		   This avoids needing to transmit `l, r`.
		*/

		// Protocol 1, inlined, since our `IpStatement` is for Protocol 2

		ipX := transcript.Challenge(new(F))

		PTerms := make([]PointPair, 0, 1+(2*len(acs.Generators.GBold)))
		for i := range l {
			PTerms = append(PTerms,
				PointPair{S: l[i], P: acs.Generators.GBold[i]},
				PointPair{S: *FE(new(F)).Multiply(&yz.YInv[i], &r[i]), P: acs.Generators.HBold[i]},
			)
		}

		PTerms = append(PTerms, PointPair{S: *FE(new(F)).Multiply(ipX, &tCaret), P: acs.Generators.G})

		if err := NewIPStatementProver[P, F, PE, FE](&acs.Generators, yz.YInv, ipX, multiexp.MultiExp(new(P), PTerms)).Prove(transcript, *NewIPWitness[F, FE](l, r)); err != nil {
			return err
		}
	}
	return nil
}

func (acs *ArithmeticCircuitStatement[P, F, PE, FE]) Verify(
	verifier *BatchVerifier[P, F, PE, FE],
	transcript *VerifierTranscript[P, F, PE, FE],
	randomReader io.Reader,
) error {
	if len(verifier.GBold) < len(acs.Generators.GBold) {
		verifier.GBold = slices.Grow(verifier.GBold, len(acs.Generators.GBold))[:len(acs.Generators.GBold)]
		verifier.HBold = slices.Grow(verifier.HBold, len(acs.Generators.GBold))[:len(acs.Generators.GBold)]
		verifier.HSum = slices.Grow(verifier.HSum, len(acs.Generators.GBold))[:len(acs.Generators.GBold)]
	}

	n := acs.NumN()
	c := acs.NumC()

	ni := (2 * c) + 2

	ilr := ni / 2
	io := ni
	is := ni + 1
	jo := 0

	AI, err := transcript.ReadPoint(new(P))
	if err != nil {
		return ErrIncompleteProof
	}

	AO, err := transcript.ReadPoint(new(P))
	if err != nil {
		return ErrIncompleteProof
	}

	S, err := transcript.ReadPoint(new(P))
	if err != nil {
		return ErrIncompleteProof
	}

	y := transcript.Challenge(new(F))
	z := transcript.Challenge(new(F))
	yz := acs.YZChallenges(y, z)

	// The fixed GBP paper writes this as `2 * (ni + 1)` (inclusive), but this is exclusive
	tPolyLen := (2 * (ni + 1)) + 1
	tBeforeNi := make([]P, 0, ni-(ni/2))
	for i := ni / 2; i < ni; i++ {
		p, err := transcript.ReadPoint(new(P))
		if err != nil {
			return ErrIncompleteProof
		}
		tBeforeNi = append(tBeforeNi, *p)
	}
	tAfterNi := make([]P, 0, tPolyLen-(ni+1))
	for i := ni + 1; i < tPolyLen; i++ {
		p, err := transcript.ReadPoint(new(P))
		if err != nil {
			return ErrIncompleteProof
		}
		tAfterNi = append(tAfterNi, *p)
	}

	x := ScalarPowers[F, FE](transcript.Challenge(new(F)), tPolyLen)

	lWeights := make(ScalarVector[F, FE], n)
	rWeights := make(ScalarVector[F, FE], n)
	oWeights := make(ScalarVector[F, FE], n)

	for i := range acs.Constraints {
		AccumulateVector(lWeights, acs.Constraints[i].WL, &yz.Z[i])
		AccumulateVector(rWeights, acs.Constraints[i].WR, &yz.Z[i])
		AccumulateVector(oWeights, acs.Constraints[i].WO, &yz.Z[i])
	}

	rWeights.MultiplyVec(yz.YInv)

	delta := slices.Clone(rWeights).InnerProduct(lWeights)

	tauX, err := transcript.ReadScalar(new(F))
	if err != nil {
		return ErrIncompleteProof
	}
	mu, err := transcript.ReadScalar(new(F))
	if err != nil {
		return ErrIncompleteProof
	}
	tCaret, err := transcript.ReadScalar(new(F))
	if err != nil {
		return ErrIncompleteProof
	}

	type PointPair = multiexp.ScalarPointPair[P, F, PE, FE]

	// Lines 88-90, modified per Generalized Bulletproofs as needed w.r.t. `t`
	// This corresponds to the verifier's final Step 4 in the 'fixed' paper
	{
		verifierWeight := curve.RandomScalar[F, FE](new(F), randomReader)

		// lhs of the equation, weighted to enable batch verification
		FE(&verifier.G).Add(&verifier.G, FE(new(F)).Multiply(tCaret, verifierWeight))
		FE(&verifier.H).Add(&verifier.H, FE(new(F)).Multiply(tauX, verifierWeight))

		// rhs of the equation, negated to cause a sum to zero

		/*
		   `delta - z...`, instead of `delta + z...`, is because we write our constraint as
		   `+ c = 0`, not `= c`, so we have to subtract it from both sides, which this effects.
		*/
		constraintsC := make(ScalarVector[F, FE], len(acs.Constraints))
		for i := range acs.Constraints {
			constraintsC[i] = acs.Constraints[i].C
		}
		cIP := slices.Clone(yz.Z).InnerProduct(constraintsC)
		FE(&verifier.G).Subtract(&verifier.G,
			FE(new(F)).Multiply(verifierWeight,
				FE(new(F)).Multiply(&x[ni],
					FE(new(F)).Subtract(&delta, &cIP),
				),
			),
		)
		VWeights := make(ScalarVector[F, FE], len(acs.V))
		for i := range acs.Constraints {
			AccumulateVector(VWeights, acs.Constraints[i].WV, &yz.Z[i])
		}

		VWeights.Multiply(&x[ni])
		for i := range VWeights {
			/*
			   We actually don't negate `verifier_weight` here as we write our constraint as
			   `... + WV V = 0` not `= WV V + ..`. This means we need to subtract it from both sides,
			   which this effects.
			*/
			verifier.Additional = append(verifier.Additional, PointPair{S: *FE(new(F)).Multiply(verifierWeight, &VWeights[i]), P: acs.V[i]})
		}
		minusVerifierWeight := FE(new(F)).Negate(verifierWeight)
		for i := range tBeforeNi {
			verifier.Additional = append(verifier.Additional, PointPair{S: *FE(new(F)).Multiply(minusVerifierWeight, &x[(ni/2)+i]), P: tBeforeNi[i]})
		}
		for i := range tAfterNi {
			verifier.Additional = append(verifier.Additional, PointPair{S: *FE(new(F)).Multiply(minusVerifierWeight, &x[ni+1+i]), P: tAfterNi[i]})
		}
	}

	// This corresponds to the verifier's final Steps 3, 5 in the 'fixed' paper
	verifierWeight := curve.RandomScalar[F, FE](new(F), randomReader)
	// Multiply `x` by `verifier_weight` as this effects `verifier_weight` onto most scalars and
	// saves a notable amount of operations
	x = x.Multiply(verifierWeight)

	// This following block effectively calculates P, within the multiexp
	{
		verifier.Additional = append(verifier.Additional,
			PointPair{S: x[ilr], P: *AI},
			PointPair{S: x[io], P: *AO},
		)
		// `h_bold' * y` is equivalent to `h_bold` as `h_bold'` _is_ `h_bold * y^{-1}`
		log2N := 0
		for (1 << log2N) != n {
			log2N++
		}
		FE(&verifier.HSum[log2N]).Subtract(&verifier.HSum[log2N], verifierWeight)
		verifier.Additional = append(verifier.Additional, PointPair{S: x[is], P: *S})

		// Lines 85-87 calculate `WL`, `WR`, `WO`
		// We preserve them in terms of `g_bold` and `h_bold` for a more efficient multiexp
		hBoldScalars := lWeights.Multiply(&x[ilr])
		rWeights.Multiply(&x[ilr])
		for i := range rWeights {
			FE(&verifier.GBold[i]).Add(&verifier.GBold[i], &rWeights[i])
		}
		hBoldScalars.AddVec(oWeights.Multiply(&x[jo]))

		for i := range acs.C {
			cg := make(ScalarVector[F, FE], n)
			for j := range acs.Constraints {
				if WCG, ok := acs.Constraints[j].WCG.Get(i); ok {
					AccumulateVector(cg, WCG, &yz.Z[j])
				}
			}

			// Push the terms for `C`, which increment from `0`, and the terms for `WC`, which
			// decrement from `n'`
			{
				C := acs.C[i]
				WCG := cg
				i := 1 + i
				j := ni - i
				verifier.Additional = append(verifier.Additional, PointPair{S: x[j], P: C})
				hBoldScalars.AddVec(WCG.Multiply(&x[i]))
			}
		}

		// All terms for `h_bold` here have actually been for `h_bold'`, `h_bold * y^{-1}`
		hBoldScalars.MultiplyVec(yz.YInv)
		for i := range hBoldScalars {
			FE(&verifier.HBold[i]).Add(&verifier.HBold[i], &hBoldScalars[i])
		}

		// Remove `mu * h` from `P`
		FE(&verifier.H).Subtract(&verifier.H, FE(new(F)).Multiply(verifierWeight, mu))
	}

	// Prove for lines 88, 92 with an Inner-Product statement
	// This inlines Protocol 1, as our IpStatement implements Protocol 2
	ipX := transcript.Challenge(new(F))

	// `P` is amended with this additional term
	FE(&verifier.G).Add(&verifier.G, FE(new(F)).Multiply(verifierWeight, FE(new(F)).Multiply(ipX, tCaret)))

	return NewIPStatementVerifier[P, F, PE, FE](&acs.Generators, yz.YInv, ipX, verifierWeight).Verify(verifier, transcript)
}
