package plus

import (
	"errors"
	"io"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type WeightedInnerProductProof[T curve25519.PointOperations] struct {
	L           []curve25519.PublicKey[T]
	R           []curve25519.PublicKey[T]
	A           curve25519.PublicKey[T]
	B           curve25519.PublicKey[T]
	RAnswer     curve25519.Scalar
	SAnswer     curve25519.Scalar
	DeltaAnswer curve25519.Scalar
}

func (wipp WeightedInnerProductProof[T]) BufferLength(signature bool) (n int) {
	if !signature {
		n += utils.UVarInt64Size(len(wipp.L)) + utils.UVarInt64Size(len(wipp.R))
	}
	return n + curve25519.PublicKeySize*2 + curve25519.PublicKeySize*len(wipp.L) + curve25519.PublicKeySize*len(wipp.R) + curve25519.PrivateKeySize*3
}

type WeightedInnerProductWitness[T curve25519.PointOperations] struct {
	A     bulletproofs.ScalarVector[T]
	B     bulletproofs.ScalarVector[T]
	Alpha curve25519.Scalar
}

type WeightedInnerProductStatement[T curve25519.PointOperations] struct {
	P curve25519.PublicKey[T]
	Y bulletproofs.ScalarVector[T]
}

func NewWeightedInnerProductStatement[T curve25519.PointOperations](P *curve25519.PublicKey[T], y *curve25519.Scalar, n int) WeightedInnerProductStatement[T] {
	if bulletproofs.PaddedPowerOfTwo(n) != n {
		panic("n must be power of two")
	}

	// y ** n
	yVec := make(bulletproofs.ScalarVector[T], n)
	yVec[0] = *y
	for i := 1; i < n; i++ {
		yVec[i] = *new(curve25519.Scalar).Multiply(&yVec[i-1], y)
	}

	return WeightedInnerProductStatement[T]{
		P: *P,
		Y: yVec,
	}
}

func (wips WeightedInnerProductStatement[T]) TranscriptLR(transcript *curve25519.Scalar, L, R *curve25519.PublicKey[T]) *curve25519.Scalar {
	return crypto.ScalarDeriveLegacy(transcript, transcript.Bytes(), L.Bytes(), R.Bytes())
}

func (wips WeightedInnerProductStatement[T]) TranscriptAB(transcript *curve25519.Scalar, A, B *curve25519.PublicKey[T]) *curve25519.Scalar {
	return crypto.ScalarDeriveLegacy(transcript, transcript.Bytes(), A.Bytes(), B.Bytes())
}

// NextGH Prover's variant of the shared code block to calculate G/H/P when n > 1
// Returns each permutation of G/H since the prover needs to do operation on each permutation
// P is dropped as it's unused in the prover's path
func (wips WeightedInnerProductStatement[T]) NextGH(transcript *curve25519.Scalar, GBold1, GBold2, HBold1, HBold2 bulletproofs.PointVector[T], L, R *curve25519.PublicKey[T], YInvNHat *curve25519.Scalar) (e, invE, eSquare, invESquare curve25519.Scalar, GBold, HBold bulletproofs.PointVector[T]) {
	e = *wips.TranscriptLR(transcript, L, R)
	invE.Invert(&e)

	eYInv := new(curve25519.Scalar).Multiply(&e, YInvNHat)

	GBold = make(bulletproofs.PointVector[T], 0, len(GBold1))
	for i := range GBold1 {
		GBold = append(GBold, *new(curve25519.PublicKey[T]).DoubleScalarMult(&invE, &GBold1[i], eYInv, &GBold2[i]))
	}
	HBold = make(bulletproofs.PointVector[T], 0, len(HBold1))
	for i := range HBold1 {
		HBold = append(HBold, *new(curve25519.PublicKey[T]).DoubleScalarMult(&e, &HBold1[i], &invE, &HBold2[i]))
	}

	eSquare.Multiply(&e, &e)
	invESquare.Multiply(&invE, &invE)

	return e, invE, eSquare, invESquare, GBold, HBold
}

func (wips WeightedInnerProductStatement[T]) Prove(transcript *curve25519.Scalar, witness WeightedInnerProductWitness[T], randomReader io.Reader) (proof WeightedInnerProductProof[T], err error) {
	if len(wips.Y) != len(witness.A) {
		return WeightedInnerProductProof[T]{}, errors.New("length mismatch")
	}

	GBold := make(bulletproofs.PointVector[T], 0, len(wips.Y))
	HBold := make(bulletproofs.PointVector[T], 0, len(wips.Y))

	for i := range wips.Y {
		GBold = append(GBold, *curve25519.FromPoint[T](bulletproofs.GeneratorPlus.G[i]))
		HBold = append(HBold, *curve25519.FromPoint[T](bulletproofs.GeneratorPlus.H[i]))
	}

	var yInv []curve25519.Scalar
	{
		i := 1
		for i < len(wips.Y) {
			yInv = append(yInv, *new(curve25519.Scalar).Invert(&wips.Y[i-1]))
			i *= 2
		}
	}

	var points []*curve25519.PublicKey[T]
	var scalars []*curve25519.Scalar

	// Check P has the expected relationship
	{
		for i := range witness.A {
			points = append(points, curve25519.FromPoint[T](bulletproofs.GeneratorPlus.G[i]))
			scalars = append(scalars, &witness.A[i])
			points = append(points, curve25519.FromPoint[T](bulletproofs.GeneratorPlus.H[i]))
			scalars = append(scalars, &witness.B[i])
		}

		wip := witness.A.WeightedInnerProduct(witness.B, wips.Y)
		points = append(points, curve25519.FromPoint[T](crypto.GeneratorH.Point))
		scalars = append(scalars, &wip)
		points = append(points, curve25519.FromPoint[T](crypto.GeneratorG.Point))
		scalars = append(scalars, &witness.Alpha)

		if new(curve25519.PublicKey[T]).MultiScalarMult(scalars, points).Equal(&wips.P) == 0 {
			return WeightedInnerProductProof[T]{}, errors.New("relationship mismatch")
		}
	}

	scalarTmp := make(bulletproofs.ScalarVector[T], len(witness.A))
	a := slices.Clone(witness.A)
	b := slices.Clone(witness.B)

	alpha := witness.Alpha

	var LSlice, RSlice []curve25519.PublicKey[T]

	var L, R curve25519.PublicKey[T]
	var dL, dR, e, invE, eSquare, invESquare curve25519.Scalar

	y := wips.Y
	// else n > 1 case from figure 1
	for len(GBold) > 1 {
		a1, a2 := a.Split()
		b1, b2 := b.Split()

		GBold1, GBold2 := GBold.Split()
		HBold1, HBold2 := HBold.Split()

		nHat := len(GBold1)
		y = y[:nHat]

		yNHat := y[nHat-1]

		curve25519.RandomScalar(&dL, randomReader)
		curve25519.RandomScalar(&dR, randomReader)

		cL := a1.WeightedInnerProduct(b2, y)
		cR := a2.WeightedWeightedInnerProduct(&yNHat, b1, y)

		// pop
		yInvNHat := yInv[len(yInv)-1]
		yInv = yInv[:len(yInv)-1]

		{
			points = points[:0]
			scalars = scalars[:0]
			a1YInv := a1.Copy(scalarTmp[:0]).Multiply(&yInvNHat)
			for i := range a1YInv {
				points = append(points, &GBold2[i])
				scalars = append(scalars, &a1YInv[i])
				points = append(points, &HBold1[i])
				scalars = append(scalars, &b2[i])
			}

			points = append(points, curve25519.FromPoint[T](crypto.GeneratorH.Point))
			scalars = append(scalars, &cL)
			points = append(points, curve25519.FromPoint[T](crypto.GeneratorG.Point))
			scalars = append(scalars, &dL)

			L.MultiScalarMult(scalars, points)
			L.ScalarMult(invEight, &L)

			LSlice = append(LSlice, L)
		}

		{
			points = points[:0]
			scalars = scalars[:0]
			a2Y := a2.Copy(scalarTmp[:0]).Multiply(&yNHat)
			for i := range a2Y {
				points = append(points, &GBold1[i])
				scalars = append(scalars, &a2Y[i])
				points = append(points, &HBold2[i])
				scalars = append(scalars, &b1[i])
			}

			points = append(points, curve25519.FromPoint[T](crypto.GeneratorH.Point))
			scalars = append(scalars, &cR)
			points = append(points, curve25519.FromPoint[T](crypto.GeneratorG.Point))
			scalars = append(scalars, &dR)

			R.MultiScalarMult(scalars, points)
			R.ScalarMult(invEight, &R)

			RSlice = append(RSlice, R)
		}

		e, invE, eSquare, invESquare, GBold, HBold = wips.NextGH(transcript, GBold1, GBold2, HBold1, HBold2, &L, &R, &yInvNHat)

		a = a1.Multiply(&e).AddVecMultiply(a2, new(curve25519.Scalar).Multiply(&yNHat, &invE))
		b = b1.Multiply(&invE).AddVecMultiply(b2, &e)
		alpha.Add(&alpha, new(curve25519.Scalar).Add(new(curve25519.Scalar).Multiply(&dL, &eSquare), new(curve25519.Scalar).Multiply(&dR, &invESquare)))
	}

	// n == 1 case from figure 1

	var r, s, delta, eta curve25519.Scalar
	curve25519.RandomScalar(&r, randomReader)
	curve25519.RandomScalar(&s, randomReader)
	curve25519.RandomScalar(&delta, randomReader)
	curve25519.RandomScalar(&eta, randomReader)

	ry := new(curve25519.Scalar).Multiply(&r, &y[0])

	var A, B curve25519.PublicKey[T]

	{
		points = points[:0]
		scalars = scalars[:0]

		points = append(points, &GBold[0])
		scalars = append(scalars, &r)
		points = append(points, &HBold[0])
		scalars = append(scalars, &s)

		points = append(points, curve25519.FromPoint[T](crypto.GeneratorH.Point))
		var tmp curve25519.Scalar
		tmp.Add(new(curve25519.Scalar).Multiply(ry, &b[0]), new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&s, &y[0]), &a[0]))
		scalars = append(scalars, &tmp)
		points = append(points, curve25519.FromPoint[T](crypto.GeneratorG.Point))
		scalars = append(scalars, &delta)

		A.MultiScalarMult(scalars, points)
		A.ScalarMult(invEight, &A)
	}

	{
		B.DoubleScalarMultPrecomputed(new(curve25519.Scalar).Multiply(ry, &s), crypto.GeneratorH, &eta, crypto.GeneratorG)
		B.ScalarMult(invEight, &B)
	}

	e = *wips.TranscriptAB(transcript, &A, &B)

	rAnswer := new(curve25519.Scalar).Add(&r, new(curve25519.Scalar).Multiply(&a[0], &e))
	sAnswer := new(curve25519.Scalar).Add(&s, new(curve25519.Scalar).Multiply(&b[0], &e))
	deltaAnswer := new(curve25519.Scalar).Add(new(curve25519.Scalar).Add(&eta, new(curve25519.Scalar).Multiply(&delta, &e)), new(curve25519.Scalar).Multiply(&alpha, new(curve25519.Scalar).Multiply(&e, &e)))

	return WeightedInnerProductProof[T]{
		L:           LSlice,
		R:           RSlice,
		A:           A,
		B:           B,
		RAnswer:     *rAnswer,
		SAnswer:     *sAnswer,
		DeltaAnswer: *deltaAnswer,
	}, nil
}

func (wips WeightedInnerProductStatement[T]) Verify(verifier *BatchVerifier[T], transcript *curve25519.Scalar, proof WeightedInnerProductProof[T], randomReader io.Reader) bool {
	var verifierWeight curve25519.Scalar
	curve25519.RandomScalar(&verifierWeight, randomReader)

	// Verify the L/R lengths
	{
		lrLen := 0
		for (1 << lrLen) < len(wips.Y) {
			lrLen++
		}
		if lrLen != len(proof.L) || lrLen != len(proof.R) || (1<<lrLen) != len(wips.Y) {
			return false
		}
	}

	invY := make([]curve25519.Scalar, 1, len(wips.Y))
	{
		invY[0].Invert(&wips.Y[0])
		for len(invY) < len(wips.Y) {
			invY = append(invY, *new(curve25519.Scalar).Multiply(&invY[0], &invY[len(invY)-1]))
		}
	}

	eIs := make([]curve25519.Scalar, 0, len(proof.L))

	for i := range proof.L {
		eIs = append(eIs, *wips.TranscriptLR(transcript, &proof.L[i], &proof.R[i]))
	}

	var A, B curve25519.PublicKey[T]
	e := *wips.TranscriptAB(transcript, &proof.A, &proof.B)
	A.MultByCofactor(&proof.A)
	B.MultByCofactor(&proof.B)

	negESquare := new(curve25519.Scalar).Multiply(&verifierWeight, new(curve25519.Scalar).Negate(new(curve25519.Scalar).Multiply(&e, &e)))

	verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *negESquare, P: wips.P})

	challenges := make([][2]curve25519.Scalar, 0, len(proof.L))

	invEIs := make([]curve25519.Scalar, len(eIs))
	//todo: batch invert
	for i := range invEIs {
		invEIs[i].Invert(&eIs[i])
	}

	var L, R curve25519.PublicKey[T]
	var eISquare, invEISquare curve25519.Scalar

	for i := range proof.L {
		eI := eIs[i]
		invEI := invEIs[i]
		L.MultByCofactor(&proof.L[i])
		R.MultByCofactor(&proof.R[i])

		challenges = append(challenges, [2]curve25519.Scalar{eI, invEI})

		eISquare.Multiply(&eI, &eI)
		invEISquare.Multiply(&invEI, &invEI)

		verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(negESquare, &eISquare), P: L})
		verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(negESquare, &invEISquare), P: R})
	}

	productCache := bulletproofs.ChallengeProducts(challenges)

	for len(verifier.GBold) < len(wips.Y) {
		verifier.GBold = append(verifier.GBold, curve25519.Scalar{})
	}
	for len(verifier.HBold) < len(wips.Y) {
		verifier.HBold = append(verifier.HBold, curve25519.Scalar{})
	}

	re := new(curve25519.Scalar).Multiply(&proof.RAnswer, &e)

	var scalar curve25519.Scalar
	for i := range wips.Y {
		scalar.Multiply(&productCache[i], re)
		if i > 0 {
			scalar.Multiply(&scalar, &invY[i-1])
		}
		verifier.GBold[i].Add(&verifier.GBold[i], new(curve25519.Scalar).Multiply(&verifierWeight, &scalar))
	}

	se := new(curve25519.Scalar).Multiply(&proof.SAnswer, &e)
	for i := range wips.Y {
		scalar.Multiply(&productCache[len(productCache)-1-i], se)
		verifier.HBold[i].Add(&verifier.HBold[i], new(curve25519.Scalar).Multiply(&verifierWeight, &scalar))
	}

	verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(&verifierWeight, new(curve25519.Scalar).Negate(&e)), P: A})
	verifier.G.Add(&verifier.G, new(curve25519.Scalar).Multiply(&verifierWeight, new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&proof.RAnswer, &wips.Y[0]), &proof.SAnswer)))
	verifier.H.Add(&verifier.H, new(curve25519.Scalar).Multiply(&verifierWeight, &proof.DeltaAnswer))
	verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Negate(&verifierWeight), P: B})

	return true
}
