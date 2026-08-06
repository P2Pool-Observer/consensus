package generalized_bulletproofs

import (
	"crypto/rand"
	"io"
	"slices"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/helioselene"
)

func TestZeroArithmeticCircuit(t *testing.T) {
	t.Run("Constant", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testZeroArithmeticCircuit[curve25519.Point, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testZeroArithmeticCircuit[helioselene.HeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testZeroArithmeticCircuit[helioselene.SelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
	t.Run("VarTime", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testZeroArithmeticCircuit[curve25519.VarTimePoint, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testZeroArithmeticCircuit[helioselene.VarTimeHeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testZeroArithmeticCircuit[helioselene.VarTimeSelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
}

func testZeroArithmeticCircuit[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]](t *testing.T, randomReader io.Reader) {
	generators, err := InsecureTestGenerator[P, F, PE, FE](1, randomReader)
	if err != nil {
		t.Fatal(err)
	}

	value := curve.RandomScalar[F, FE](new(F), randomReader)
	gamma := curve.RandomScalar[F, FE](new(F), randomReader)
	commitment := PE(new(P)).DoubleScalarMult(value, &generators.G, gamma, &generators.H)

	V := []P{*commitment}

	aL := []F{*FE(new(F)).Zero()}
	aR := slices.Clone(aL)

	context := [32]byte{}

	transcript := NewTranscript[P, F, PE, FE](context)
	commitments := transcript.WriteCommitments(nil, V)
	statement, err := NewArithmeticCircuitStatement[P, F, PE, FE](generators.Reduce(1), nil, commitments)
	if err != nil {
		t.Fatal(err)
	}
	witness := NewArithmeticCircuitWitness[P, F, PE, FE](aL, aR, nil, []PedersenCommitment[P, F, PE, FE]{{Value: *value, Mask: *gamma}})

	if err = statement.Prove(transcript, witness, randomReader); err != nil {
		t.Fatal(err)
	}
	proof := transcript.Complete()

	var verifier BatchVerifier[P, F, PE, FE]
	verifierTranscript := NewVerifierTranscript[P, F, PE, FE](context, proof)
	verifierCommitments, err := verifierTranscript.ReadCommitments(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(verifierCommitments.C, commitments.C, func(p P, p2 P) bool {
		return PE(&p).Equal(&p2) == 1
	}) || !slices.EqualFunc(verifierCommitments.V, commitments.V, func(p P, p2 P) bool {
		return PE(&p).Equal(&p2) == 1
	}) {
		t.Fatal("not equal commitments")
	}
	if err = statement.Verify(&verifier, verifierTranscript, randomReader); err != nil {
		t.Fatal(err)
	}
	if !verifier.Verify(generators) {
		t.Fatal("could not verify proof")
	}

}

func TestVectorCommitmentArithmeticCircuit(t *testing.T) {
	t.Run("Constant", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testVectorCommitmentArithmeticCircuit[curve25519.Point, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testVectorCommitmentArithmeticCircuit[helioselene.HeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testVectorCommitmentArithmeticCircuit[helioselene.SelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
	t.Run("VarTime", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testVectorCommitmentArithmeticCircuit[curve25519.VarTimePoint, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testVectorCommitmentArithmeticCircuit[helioselene.VarTimeHeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testVectorCommitmentArithmeticCircuit[helioselene.VarTimeSelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
}

func testVectorCommitmentArithmeticCircuit[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]](t *testing.T, randomReader io.Reader) {
	generators, err := InsecureTestGenerator[P, F, PE, FE](2, randomReader)
	if err != nil {
		t.Fatal(err)
	}
	reduced := generators.Reduce(2)

	v1 := curve.RandomScalar[F, FE](new(F), randomReader)
	v2 := curve.RandomScalar[F, FE](new(F), randomReader)
	gamma := curve.RandomScalar[F, FE](new(F), randomReader)
	commitment := PE(new(P)).Add(
		PE(new(P)).DoubleScalarMult(v1, &generators.GBold[0], v2, &generators.GBold[1]),
		PE(new(P)).ScalarMult(gamma, &generators.H),
	)

	var V []P
	C := []P{*commitment}

	zeroVec := []F{*FE(new(F)).Zero()}

	aL := slices.Clone(zeroVec)
	aR := slices.Clone(zeroVec)

	context := [32]byte{}

	transcript := NewTranscript[P, F, PE, FE](context)
	commitments := transcript.WriteCommitments(C, V)
	statement, err := NewArithmeticCircuitStatement[P, F, PE, FE](
		reduced,
		[]LinComb[F, FE]{
			*NewEmptyLinComb[F, FE]().
				Term(FE(new(F)).One(), VariableCG{Commitment: 0, Index: 0}).
				Term(curve.ScalarFromUint64[F, FE](new(F), 2), VariableCG{Commitment: 0, Index: 1}).
				Constant(FE(new(F)).Negate(FE(new(F)).Add(v1, FE(new(F)).Add(v2, v2)))),
		},
		commitments,
	)
	if err != nil {
		t.Fatal(err)
	}
	witness := NewArithmeticCircuitWitness[P, F, PE, FE](aL, aR, []PedersenVectorCommitment[P, F, PE, FE]{{GValues: []F{*v1, *v2}, Mask: *gamma}}, nil)

	if err = statement.Prove(transcript, witness, randomReader); err != nil {
		t.Fatal(err)
	}
	proof := transcript.Complete()

	var verifier BatchVerifier[P, F, PE, FE]
	verifierTranscript := NewVerifierTranscript[P, F, PE, FE](context, proof)
	verifierCommitments, err := verifierTranscript.ReadCommitments(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(verifierCommitments.C, commitments.C, func(p P, p2 P) bool {
		return PE(&p).Equal(&p2) == 1
	}) || !slices.EqualFunc(verifierCommitments.V, commitments.V, func(p P, p2 P) bool {
		return PE(&p).Equal(&p2) == 1
	}) {
		t.Fatal("not equal commitments")
	}
	if err = statement.Verify(&verifier, verifierTranscript, randomReader); err != nil {
		t.Fatal(err)
	}
	if !verifier.Verify(generators) {
		t.Fatal("could not verify proof")
	}
}
