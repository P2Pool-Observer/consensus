package plus

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

func TestZeroWeightedInnerProduct(t *testing.T) {
	rng := crypto.NewDeterministicTestGenerator()

	P := curve25519.FromPoint[curve25519.VarTimeOperations](edwards25519.NewIdentityPoint())
	var y edwards25519.Scalar
	curve25519.RandomScalar(&y, rng)

	statement := NewWeightedInnerProductStatement(P, &y, 1)
	witness := WeightedInnerProductWitness[curve25519.VarTimeOperations]{
		A:     make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], 1),
		B:     make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], 1),
		Alpha: curve25519.Scalar{},
	}

	var transcript curve25519.Scalar
	curve25519.RandomScalar(&transcript, rng)
	proof, err := statement.Prove(new(curve25519.Scalar).Set(&transcript), witness, rng)
	if err != nil {
		t.Fatalf("failed to prove inner product: %v", err)
	}

	var verifier BatchVerifier[curve25519.VarTimeOperations]

	if !statement.Verify(&verifier, &transcript, proof, rng) {
		t.Fatalf("failed to verify inner product: %s", err)
	}

	if !verifier.Verify() {
		t.Fatalf("failed to verify inner product")
	}
}

func TestWeightedInnerProduct(t *testing.T) {
	rng := crypto.NewDeterministicTestGenerator()

	// P = sum(g_bold * a, h_bold * b, g * (a * y * b), h * alpha)

	var verifier BatchVerifier[curve25519.VarTimeOperations]

	for _, i := range []int{1, 2, 4, 8, 16, 32} {
		GBold := make(bulletproofs.PointVector[curve25519.VarTimeOperations], 0, i)
		HBold := make(bulletproofs.PointVector[curve25519.VarTimeOperations], 0, i)

		for j := range i {
			GBold = append(GBold, *curve25519.FromPoint[curve25519.VarTimeOperations](bulletproofs.GeneratorPlus.G[j]))
			HBold = append(HBold, *curve25519.FromPoint[curve25519.VarTimeOperations](bulletproofs.GeneratorPlus.H[j]))
		}

		a := make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], i)
		b := make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], i)

		var alpha curve25519.Scalar
		curve25519.RandomScalar(&alpha, rng)

		var y curve25519.Scalar
		curve25519.RandomScalar(&y, rng)

		yVec := make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], len(GBold))
		yVec[0] = y
		for i := 1; i < len(yVec); i++ {
			yVec[i].Multiply(&yVec[i-1], &y)
		}

		for j := range i {
			curve25519.RandomScalar(&a[j], rng)
			curve25519.RandomScalar(&b[j], rng)
		}

		wip := a.WeightedInnerProduct(b, yVec)

		P := GBold.MultiplyScalars(new(curve25519.VarTimePublicKey), a)
		P.Add(P, HBold.MultiplyScalars(new(curve25519.VarTimePublicKey), b))
		P.Add(P, new(curve25519.VarTimePublicKey).DoubleScalarMultPrecomputed(&wip, crypto.GeneratorH, &alpha, crypto.GeneratorG))

		statement := NewWeightedInnerProductStatement(P, &y, i)
		witness := WeightedInnerProductWitness[curve25519.VarTimeOperations]{
			A:     a,
			B:     b,
			Alpha: alpha,
		}

		var transcript curve25519.Scalar
		curve25519.RandomScalar(&transcript, rng)
		proof, err := statement.Prove(new(curve25519.Scalar).Set(&transcript), witness, rng)
		if err != nil {
			t.Fatalf("failed to prove inner product: %v", err)
		}
		if !statement.Verify(&verifier, &transcript, proof, rng) {
			t.Fatalf("failed to verify inner product: %s", err)
		}
	}

	if !verifier.Verify() {
		t.Fatalf("failed to verify inner product")
	}
}
