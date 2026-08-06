package generalized_bulletproofs

import (
	"errors"
	"math"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// IPStatement TODO: remove PE on Go 1.27
type IPStatement[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]] struct {
	Generators   ProofGenerators[P]
	HBoldWeights ScalarVector[F, FE]
	U            F

	VerifierWeight *F
	ProverG        *P
}

func (ips *IPStatement[P, F, PE, FE]) IsVerifier() bool {
	return ips.VerifierWeight != nil
}

func (ips *IPStatement[P, F, PE, FE]) IsProver() bool {
	return ips.ProverG != nil
}

func NewIPStatementProver[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]](generators *ProofGenerators[P], hBoldWeights ScalarVector[F, FE], u *F, proverG *P) *IPStatement[P, F, PE, FE] {
	if len(generators.HBold) != len(hBoldWeights) {
		return nil
	}
	return &IPStatement[P, F, PE, FE]{
		Generators:   *generators,
		HBoldWeights: hBoldWeights,
		U:            *u,
		ProverG:      PE(new(P)).Set(proverG),
	}
}

func NewIPStatementVerifier[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]](generators *ProofGenerators[P], hBoldWeights ScalarVector[F, FE], u *F, verifierWeight *F) *IPStatement[P, F, PE, FE] {
	if len(generators.HBold) != len(hBoldWeights) {
		return nil
	}
	return &IPStatement[P, F, PE, FE]{
		Generators:     *generators,
		HBoldWeights:   hBoldWeights,
		U:              *u,
		VerifierWeight: FE(new(F)).Set(verifierWeight),
	}
}

var ErrIncorrectAmountOfGenerators = errors.New("incorrect amount of generators")
var ErrInconsistentWitness = errors.New("inconsistent witness")
var ErrIncompleteProof = errors.New("incomplete proof")

func (ips *IPStatement[P, F, PE, FE]) Prove(transcript *Transcript[P, F, PE, FE], witness IPWitness[F, FE]) (err error) {
	type PointPair = multiexp.ScalarPointPair[P, F, PE, FE]
	gBold, hBold, u, p, a, b, err := func() (gBold, hBold PointVector[P, F, PE, FE], u, p *P, a, b ScalarVector[F, FE], err error) {
		u = PE(new(P)).ScalarMult(&ips.U, &ips.Generators.G)

		if len(witness.A) > (math.MaxInt>>1)+1 {
			return nil, nil, nil, nil, nil, nil, ErrIncorrectAmountOfGenerators
		}
		if len(ips.Generators.GBold) < utils.NextPowerOfTwo(uint(len(witness.A))) {
			return nil, nil, nil, nil, nil, nil, ErrIncorrectAmountOfGenerators
		}

		gBold = PointVector[P, F, PE, FE](slices.Clone(ips.Generators.GBold))
		hBold = PointVector[P, F, PE, FE](slices.Clone(ips.Generators.HBold)).MultiplyVec(ips.HBoldWeights)

		a, b = witness.A, witness.B

		if !ips.IsProver() {
			return nil, nil, nil, nil, nil, nil, errors.New("prove called with a P specification which was for the verifier")
		}

		p = ips.ProverG

		// debug
		if debugChecks {
			// Ensure this witness actually opens this statement
			var pairs []PointPair
			for i := range a {
				pairs = append(pairs, PointPair{
					S: a[i],
					P: gBold[i],
				})
			}
			for i := range b {
				pairs = append(pairs, PointPair{
					S: b[i],
					P: hBold[i],
				})
			}
			pairs = append(pairs, PointPair{
				S: a.InnerProduct(b),
				P: *u,
			})
			if PE(multiexp.MultiExp[P, F, PE, FE](new(P), pairs)).Equal(p) == 0 {
				return nil, nil, nil, nil, nil, nil, ErrInconsistentWitness
			}
		}

		return gBold, hBold, u, p, a, b, nil
	}()
	if err != nil {
		return err
	}

	// `else: (n > 1)` case, lines 18-35 of the Bulletproofs paper
	// This interprets `g_bold.len()` as `n`
	for len(gBold) > 1 {
		// Split a, b, g_bold, h_bold as needed for lines 20-24
		splitAt := utils.NextPowerOfTwo(uint(len(a))) / 2
		a1, a2 := a.Split(splitAt)
		b1, b2 := b.Split(splitAt)

		gBold1, gBold2 := gBold.Split()
		hBold1, hBold2 := hBold.Split()

		//nHat := len(gBold1)
		// sanity TODO find sanity

		// cl, cr, lines 21-22
		cl := b2.InnerProductUnchecked(a1)
		cr := a2.InnerProductUnchecked(b1)

		var L, R P
		{
			LTerms := make([]PointPair, 0, 1+(2*len(gBold1)))
			for i := range a1 {
				LTerms = append(LTerms, PointPair{S: a1[i], P: gBold2[i]})
			}
			for i := range b2 {
				LTerms = append(LTerms, PointPair{S: b2[i], P: hBold1[i]})
			}
			LTerms = append(LTerms, PointPair{S: cl, P: *u})
			multiexp.MultiExp(&L, LTerms)
		}
		{
			RTerms := make([]PointPair, 0, 1+(2*len(gBold1)))
			for i := range a2 {
				RTerms = append(RTerms, PointPair{S: a2[i], P: gBold1[i]})
			}
			for i := range b1 {
				RTerms = append(RTerms, PointPair{S: b1[i], P: hBold2[i]})
			}
			RTerms = append(RTerms, PointPair{S: cr, P: *u})
			multiexp.MultiExp(&R, RTerms)
		}

		// Now that we've calculate L, R, transcript them to receive x (26-27)
		transcript.PushPoint(&L)
		transcript.PushPoint(&R)
		x := transcript.Challenge(new(F))
		xInv := FE(new(F)).Invert(x)

		// The prover and verifier now calculate the following (28-31)
		gBold = make(PointVector[P, F, PE, FE], 0, len(gBold1))
		for i := range gBold1 {
			gBold = append(gBold, *multiexp.MultiExp(new(P), []PointPair{{S: *xInv, P: gBold1[i]}, {S: *x, P: gBold2[i]}}))
		}
		hBold = make(PointVector[P, F, PE, FE], 0, len(hBold1))
		for i := range hBold1 {
			hBold = append(hBold, *multiexp.MultiExp(new(P), []PointPair{{S: *x, P: hBold1[i]}, {S: *xInv, P: hBold2[i]}}))
		}
		// P = (L * (x * x)) + P + (R * (x_inv * x_inv));
		PE(p).Add(p, PE(new(P)).ScalarMult(FE(new(F)).Multiply(x, x), &L))
		PE(p).Add(p, PE(new(P)).ScalarMult(FE(new(F)).Multiply(xInv, xInv), &R))

		// 32-34
		a = a1.Multiply(x)
		a2 = a2.Multiply(xInv)
		a.AddVecUnchecked(a2)

		b = b1.Multiply(xInv)
		b2 = b2.Multiply(x)
		b.AddVecUnchecked(b2)
	}

	// `if n = 1` case from line 14-17

	// We simply send a/b
	transcript.PushScalar(&a[0])
	transcript.PushScalar(&b[0])

	return nil
}

// ChallengeProducts Produce the products of a list of challenges
//
//	This has room for optimization worth investigating further. It currently takes
//	an iterative approach. It can be optimized further via divide and conquer.
//
//	Assume there are 4 challenges.
//
//	Iterative approach (current):
//	  1. Do the optimal multiplications across challenge column 0 and 1.
//	  2. Do the optimal multiplications across that result and column 2.
//	  3. Do the optimal multiplications across that result and column 3.
//
//	Divide and conquer (worth investigating further):
//	  1. Do the optimal multiplications across challenge column 0 and 1.
//	  2. Do the optimal multiplications across challenge column 2 and 3.
//	  3. Multiply both results together.
//
//	When there are 4 challenges (n=16), the iterative approach does 28 multiplications
//	versus divide and conquer's 24.
func (ips *IPStatement[P, F, PE, FE]) ChallengeProducts(challenges [][2]F) []F {
	products := make([]F, 1<<len(challenges))
	for i := range products {
		FE(&products[i]).One()
	}

	if len(challenges) > 0 {
		products[0] = challenges[0][1]
		products[1] = challenges[0][0]

		for j := 1; j < len(challenges); j++ {
			challenge := challenges[j]
			slots := (1 << (j + 1)) - 1
			for slots > 0 {
				FE(&products[slots]).Multiply(&products[slots/2], &challenge[0])
				FE(&products[slots-1]).Multiply(&products[slots/2], &challenge[1])

				slots = max(0, slots-2)
			}
		}

		// Sanity check since if the above failed to populate, it'd be critical
		if debugChecks {
			for i := range products {
				if FE(&products[i]).IsZero() == 1 {
					panic("product is zero")
				}
			}
		}
	}
	return products
}

func (ips *IPStatement[P, F, PE, FE]) Verify(verifier *BatchVerifier[P, F, PE, FE], transcript *VerifierTranscript[P, F, PE, FE]) (err error) {
	if len(verifier.GBold) < len(ips.Generators.GBold) {
		verifier.GBold = slices.Grow(verifier.GBold, len(ips.Generators.GBold))[:len(ips.Generators.GBold)]
	}
	if len(verifier.HBold) < len(ips.Generators.GBold) {
		verifier.HBold = slices.Grow(verifier.HBold, len(ips.Generators.GBold))[:len(ips.Generators.GBold)]
	}

	// Calculate the discrete log w.r.t. 2 for the amount of generators present
	lrLen := 0
	for (1 << lrLen) < len(ips.Generators.GBold) {
		lrLen++
	}

	if !ips.IsVerifier() {
		return errors.New("verify called with a P specification which was for the prover")
	}

	weight := ips.VerifierWeight

	// Again, we start with the `else: (n > 1)` case

	// We need x, x_inv per lines 25-27 for lines 28-31

	L := make([]P, 0, lrLen)
	R := make([]P, 0, lrLen)
	xs := make([]F, 0, lrLen)
	for range lrLen {
		LP, err := transcript.ReadPoint(new(P))
		if err != nil {
			return err
		}
		L = append(L, *LP)
		RP, err := transcript.ReadPoint(new(P))
		if err != nil {
			return err
		}
		R = append(R, *RP)
		xs = append(xs, *transcript.Challenge(new(F)))
	}

	// We calculate their inverse in batch
	xInvs := slices.Clone(xs)
	curve.BatchInvert[F, FE](new(F), utils.ValuesToPointers(xInvs)...)

	// Now, with x and x_inv, we need to calculate g_bold', h_bold', P'
	//
	// For the sake of performance, we solely want to calculate all of these in terms of scalings
	// for g_bold, h_bold, P, and don't want to actually perform intermediary scalings of the
	// points
	//
	// L and R are easy, as it's simply x**2, x**-2
	//
	// For the series of g_bold, h_bold, we use the `challenge_products` function
	// For how that works, please see its own documentation

	var productCache []F
	{
		challenges := make([][2]F, 0, lrLen)
		verifier.Additional = slices.Grow(verifier.Additional, len(verifier.Additional)+2*lrLen)
		for i := range xs {
			challenges = append(challenges, [2]F{xs[i], xInvs[i]})
			verifier.Additional = append(verifier.Additional,
				multiexp.ScalarPointPair[P, F, PE, FE]{S: *FE(new(F)).Multiply(weight, FE(new(F)).Square(&xs[i])), P: L[i]},
				multiexp.ScalarPointPair[P, F, PE, FE]{S: *FE(new(F)).Multiply(weight, FE(new(F)).Square(&xInvs[i])), P: R[i]},
			)
		}

		productCache = ips.ChallengeProducts(challenges)
	}

	// And now for the `if n = 1` case
	a, err := transcript.ReadScalar(new(F))
	if err != nil {
		return ErrIncompleteProof
	}
	b, err := transcript.ReadScalar(new(F))
	if err != nil {
		return ErrIncompleteProof
	}
	c := FE(new(F)).Multiply(a, b)

	// The multiexp of these terms equate to the final permutation of P
	// We now add terms for a * g_bold' + b * h_bold' b + c * u, with the scalars negative such
	// that the terms sum to 0 for an honest prover

	// The g_bold * a term case from line 16
	for i := range ips.Generators.GBold {
		FE(&verifier.GBold[i]).Subtract(
			&verifier.GBold[i],
			FE(new(F)).Multiply(
				weight,
				FE(new(F)).Multiply(&productCache[i], a),
			),
		)
	}

	// The h_bold * b term case from line 16
	for i := range ips.Generators.HBold {
		FE(&verifier.HBold[i]).Subtract(
			&verifier.HBold[i],
			FE(new(F)).Multiply(
				weight,
				FE(new(F)).Multiply(
					&productCache[len(productCache)-1-i],
					FE(new(F)).Multiply(&ips.HBoldWeights[i], b),
				),
			),
		)
	}

	// The c * u term case from line 16
	FE(&verifier.G).Subtract(
		&verifier.G,
		FE(new(F)).Multiply(
			weight,
			FE(new(F)).Multiply(c, &ips.U),
		),
	)

	return nil
}

type IPWitness[F any, FE curve.BasicField[F]] struct {
	A ScalarVector[F, FE]
	B ScalarVector[F, FE]
}

func NewIPWitness[F any, FE curve.BasicField[F]](a, b ScalarVector[F, FE]) *IPWitness[F, FE] {
	if len(a) != len(b) {
		return nil
	}
	if len(a) == 0 {
		// If no IPA rows were used, pad to have a length of one
		return &IPWitness[F, FE]{
			A: ScalarVector[F, FE]{*FE(new(F)).Zero()},
			B: ScalarVector[F, FE]{*FE(new(F)).Zero()},
		}
	}

	return &IPWitness[F, FE]{
		// TODO: clone?
		A: a,
		B: b,
	}
}
