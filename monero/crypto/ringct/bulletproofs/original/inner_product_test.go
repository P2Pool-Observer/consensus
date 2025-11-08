package original

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
)

var one = *ringct.AmountToScalar(new(curve25519.Scalar), 1)

func TestZeroInnerProduct(t *testing.T) {
	rng := crypto.NewDeterministicTestGenerator()

	statement := InnerProductStatement[curve25519.VarTimeOperations]{
		HBoldWeights: []curve25519.Scalar{one},
		U:            one,
	}

	witness := InnerProductWitness[curve25519.VarTimeOperations]{
		A: make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], 1),
		B: make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], 1),
	}

	var transcript curve25519.Scalar
	curve25519.RandomScalar(&transcript, rng)
	proof, err := statement.Prove(transcript, witness)
	if err != nil {
		t.Fatalf("failed to prove inner product: %v", err)
	}

	var verifier BatchVerifier[curve25519.VarTimeOperations]
	verifier.GBold = make([]curve25519.Scalar, 1)
	verifier.HBold = make([]curve25519.Scalar, 1)

	var weight curve25519.Scalar
	curve25519.RandomScalar(&weight, rng)

	if err = statement.Verify(&verifier, 1, transcript, weight, proof); err != nil {
		t.Fatalf("failed to verify inner product: %s", err)
	}

	if !verifier.Verify() {
		t.Fatalf("failed to verify inner product")
	}
}

func TestInnerProduct(t *testing.T) {
	rng := crypto.NewDeterministicTestGenerator()

	// P = sum(g_bold * a, h_bold * b, g * u * <a, b>)
	var verifier BatchVerifier[curve25519.VarTimeOperations]
	verifier.GBold = make([]curve25519.Scalar, 32)
	verifier.HBold = make([]curve25519.Scalar, 32)

	for _, i := range []int{1, 2, 4, 8, 16, 32} {
		g := curve25519.FromPoint[curve25519.VarTimeOperations](crypto.GeneratorH.Point)

		var GBold, HBold bulletproofs.PointVector[curve25519.VarTimeOperations]
		for j := range i {
			GBold = append(GBold, *curve25519.FromPoint[curve25519.VarTimeOperations](bulletproofs.Generator.G[j]))
			HBold = append(HBold, *curve25519.FromPoint[curve25519.VarTimeOperations](bulletproofs.Generator.H[j]))
		}

		a := make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], i)
		b := make(bulletproofs.ScalarVector[curve25519.VarTimeOperations], i)

		for j := range i {
			curve25519.RandomScalar(&a[j], rng)
			curve25519.RandomScalar(&b[j], rng)
		}

		P := new(curve25519.VarTimePublicKey).Add(GBold.MultiplyScalars(new(curve25519.VarTimePublicKey), a), HBold.MultiplyScalars(new(curve25519.VarTimePublicKey), b))
		ip := a.InnerProduct(b)
		P.Add(P, new(curve25519.VarTimePublicKey).ScalarMult(&ip, g))

		oneVec := make([]curve25519.Scalar, i)
		for j := range oneVec {
			oneVec[j] = one
		}

		statement := InnerProductStatement[curve25519.VarTimeOperations]{
			HBoldWeights: oneVec,
			U:            one,
		}
		witness := InnerProductWitness[curve25519.VarTimeOperations]{
			A: a,
			B: b,
		}
		var transcript curve25519.Scalar
		curve25519.RandomScalar(&transcript, rng)

		proof, err := statement.Prove(transcript, witness)
		if err != nil {
			t.Fatalf("failed to prove inner product: %v", err)
		}

		var weight curve25519.Scalar
		curve25519.RandomScalar(&weight, rng)

		verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[curve25519.VarTimeOperations]{
			S: weight,
			P: *P,
		})
		if err = statement.Verify(&verifier, i, transcript, weight, proof); err != nil {
			t.Fatalf("failed to verify inner product: %s", err)
		}
	}

	if !verifier.Verify() {
		t.Fatalf("failed to verify inner product")
	}
}
