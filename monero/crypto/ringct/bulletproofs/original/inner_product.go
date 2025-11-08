package original

import (
	"errors"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// InnerProductStatement The Bulletproofs Inner-Product statement.
//
// This is for usage with Protocol 2 from the Bulletproofs paper.
type InnerProductStatement[T curve25519.PointOperations] struct {
	// HBoldWeights Weights for h_bold
	HBoldWeights bulletproofs.ScalarVector[T]
	// U as the discrete logarithm of G
	U curve25519.Scalar
}

func (ips InnerProductStatement[T]) TranscriptLR(transcript curve25519.Scalar, L, R *curve25519.PublicKey[T]) (out curve25519.Scalar) {
	crypto.ScalarDeriveLegacy(&out, transcript.Bytes(), L.Slice(), R.Slice())
	return out
}

// Prove for this Inner-Product statement.
func (ips InnerProductStatement[T]) Prove(transcript curve25519.Scalar, witness InnerProductWitness[T]) (proof InnerProductProof[T], err error) {
	GBoldSlice := bulletproofs.Generator.G[:len(witness.A)]
	HBoldSlice := bulletproofs.Generator.H[:len(witness.A)]

	var u curve25519.PublicKey[T]
	u.ScalarMultPrecomputed(&ips.U, crypto.GeneratorH)

	if len(ips.HBoldWeights) != len(HBoldSlice) {
		return InnerProductProof[T]{}, errors.New("incorrect amount of weights")
	}

	GBold := make(bulletproofs.PointVector[T], len(GBoldSlice))
	for i := range GBold {
		GBold[i] = *curve25519.FromPoint[T](GBoldSlice[i])
	}
	HBold := make(bulletproofs.PointVector[T], len(HBoldSlice))
	for i := range HBold {
		HBold[i] = *curve25519.FromPoint[T](HBoldSlice[i])
	}
	HBold.MultiplyVec(ips.HBoldWeights)

	a := slices.Clone(witness.A)
	b := slices.Clone(witness.B)

	var LSlice, RSlice []curve25519.PublicKey[T]
	var L, R curve25519.PublicKey[T]

	// `else: (n > 1)` case, lines 18-35 of the Bulletproofs paper
	// This interprets `g_bold.len()` as `n`
	for len(GBold) > 1 {
		// Split a, b, g_bold, h_bold as needed for lines 20-24
		a1, a2 := a.Split()
		b1, b2 := b.Split()

		GBold1, GBold2 := GBold.Split()
		HBold1, HBold2 := HBold.Split()

		//nhat := len(GBold1)

		// cl, cr, lines 21-22
		cl := slices.Clone(a1).InnerProduct(b2)
		cr := slices.Clone(a2).InnerProduct(b1)

		{
			L.Add(GBold2.MultiplyScalars(new(curve25519.PublicKey[T]), a1), HBold1.MultiplyScalars(new(curve25519.PublicKey[T]), b2))
			L.Add(&L, new(curve25519.PublicKey[T]).ScalarMult(&cl, &u))
			L.ScalarMult(invEight, &L)
		}
		LSlice = append(LSlice, L)

		{
			R.Add(GBold1.MultiplyScalars(new(curve25519.PublicKey[T]), a2), HBold2.MultiplyScalars(new(curve25519.PublicKey[T]), b1))
			R.Add(&R, new(curve25519.PublicKey[T]).ScalarMult(&cr, &u))
			R.ScalarMult(invEight, &R)
		}
		RSlice = append(RSlice, R)

		// Now that we've calculate L, R, transcript them to receive x (26-27)

		transcript = ips.TranscriptLR(transcript, &LSlice[len(LSlice)-1], &RSlice[len(RSlice)-1])

		x := transcript
		xInv := new(curve25519.Scalar).Invert(&x)

		// The prover and verifier now calculate the following (28-31)
		GBold = make(bulletproofs.PointVector[T], 0, len(GBold1))
		for i := range GBold1 {
			GBold = append(GBold, *new(curve25519.PublicKey[T]).DoubleScalarMult(xInv, &GBold1[i], &x, &GBold2[i]))
		}
		HBold = make(bulletproofs.PointVector[T], 0, len(HBold1))
		for i := range HBold1 {
			HBold = append(HBold, *new(curve25519.PublicKey[T]).DoubleScalarMult(&x, &HBold1[i], xInv, &HBold2[i]))
		}

		// 32-34
		a = slices.Clone(a1).Multiply(&x).AddVec(slices.Clone(a2).Multiply(xInv))
		b = slices.Clone(b1).Multiply(xInv).AddVec(slices.Clone(b2).Multiply(&x))
	}

	// `if n = 1` case from line 14-17

	return InnerProductProof[T]{
		L: LSlice,
		R: RSlice,
		A: a[0],
		B: b[0],
	}, nil
}

var ErrIncorrectAmountOfGenerators = errors.New("incorrect amount of generators")
var ErrDifferingLRLengths = errors.New("differing LR lengths")

func (ips InnerProductStatement[T]) Verify(verifier *BatchVerifier[T], ipRows int, transcript, verifierWeight curve25519.Scalar, proof InnerProductProof[T]) (err error) {
	GBoldSlice := bulletproofs.Generator.G[:ipRows]
	HBoldSlice := bulletproofs.Generator.H[:ipRows]

	// Verify the L/R lengths
	{
		// Calculate the discrete log w.r.t. 2 for the amount of generators present
		lrLen := 0
		for (1 << lrLen) < len(GBoldSlice) {
			lrLen++
		}

		// This proof has less/more terms than the passed in generators are for
		if len(proof.L) != lrLen {
			return ErrIncorrectAmountOfGenerators
		}

		if len(proof.L) != len(proof.R) {
			return ErrDifferingLRLengths
		}

	}

	// Again, we start with the `else: (n > 1)` case
	// We need x, x_inv per lines 25-27 for lines 28-31
	xs := make([]curve25519.Scalar, 0, len(proof.L))
	for i := range proof.L {
		transcript = ips.TranscriptLR(transcript, &proof.L[i], &proof.R[i])
		xs = append(xs, transcript)
	}

	// We calculate their inverse in batch
	//todo: batch invert
	xInvs := slices.Clone(xs)
	for i := range xInvs {
		xInvs[i].Invert(&xInvs[i])
	}

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

	challenges := make([][2]curve25519.Scalar, 0, len(proof.L))

	for i := range xs {
		x := xs[i]
		xInv := xInvs[i]
		L := proof.L[i]
		R := proof.R[i]

		challenges = append(challenges, [2]curve25519.Scalar{x, xInv})

		L.MultByCofactor(&L)
		R.MultByCofactor(&R)

		verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(&verifierWeight, new(curve25519.Scalar).Multiply(&x, &x)), P: L})
		verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(&verifierWeight, new(curve25519.Scalar).Multiply(&xInv, &xInv)), P: R})
	}

	productCache := bulletproofs.ChallengeProducts(challenges)

	// And now for the `if n = 1` case
	c := new(curve25519.Scalar).Multiply(&proof.A, &proof.B)

	// The multiexp of these terms equate to the final permutation of P
	// We now add terms for a * g_bold' + b * h_bold' b + c * u, with the scalars negative such
	// that the terms sum to 0 for an honest prover

	// The g_bold * a term case from line 16
	for i := range GBoldSlice {
		verifier.GBold[i].Subtract(&verifier.GBold[i], new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&verifierWeight, &productCache[i]), &proof.A))
	}
	// The h_bold * b term case from line 16
	for i := range HBoldSlice {
		verifier.HBold[i].Subtract(&verifier.HBold[i], new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&verifierWeight, &productCache[len(productCache)-1-i]), new(curve25519.Scalar).Multiply(&ips.HBoldWeights[i], &proof.B)))
	}
	// The c * u term case from line 16
	verifier.H.Subtract(&verifier.H, new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&verifierWeight, c), &ips.U))

	return nil
}

type InnerProductWitness[T curve25519.PointOperations] struct {
	A bulletproofs.ScalarVector[T]
	B bulletproofs.ScalarVector[T]
}

func NewInnerProductWitness[T curve25519.PointOperations](a, b bulletproofs.ScalarVector[T]) InnerProductWitness[T] {
	if len(a) == 0 || len(a) != len(b) {
		panic("invalid arguments")
	}

	powerOfTwo := 1
	for powerOfTwo < len(a) {
		powerOfTwo <<= 1
	}

	if powerOfTwo != len(a) {
		panic("invalid arguments")
	}
	return InnerProductWitness[T]{
		A: a,
		B: b,
	}
}

type InnerProductProof[T curve25519.PointOperations] struct {
	L []curve25519.PublicKey[T]
	R []curve25519.PublicKey[T]
	A curve25519.Scalar
	B curve25519.Scalar
}

func (ipp InnerProductProof[T]) BufferLength(signature bool) (n int) {
	if !signature {
		n += utils.UVarInt64Size(len(ipp.L)) + utils.UVarInt64Size(len(ipp.R))
	}
	return n + curve25519.PublicKeySize*len(ipp.L) + curve25519.PublicKeySize*len(ipp.R) + curve25519.PrivateKeySize*2
}
