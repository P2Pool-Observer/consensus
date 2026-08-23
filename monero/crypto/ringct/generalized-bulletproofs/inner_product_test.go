package generalized_bulletproofs

import (
	"crypto/rand"
	"io"
	"slices"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/helioselene"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func TestZeroInnerProduct(t *testing.T) {
	t.Run("Constant", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testZeroInnerProduct[curve25519.Point, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testZeroInnerProduct[helioselene.HeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testZeroInnerProduct[helioselene.SelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
	t.Run("VarTime", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testZeroInnerProduct[curve25519.VarTimePoint, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testZeroInnerProduct[helioselene.VarTimeHeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testZeroInnerProduct[helioselene.VarTimeSelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
}

func testZeroInnerProduct[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]](t *testing.T, randomReader io.Reader) {
	identity := PE(new(P)).Identity()
	generators, err := InsecureTestGenerator[P, F, PE, FE](1, randomReader)
	if err != nil {
		t.Fatal(err)
	}
	reduced := generators.Reduce(1)
	witness := NewIPWitness[F, FE](make(ScalarVector[F, FE], 1), make(ScalarVector[F, FE], 1))

	context := [32]byte{}

	proof, err := func() ([]byte, error) {
		transcript := NewTranscript[P, F](context)
		if err := NewIPStatementProver[P, F, PE, FE](
			reduced,
			ScalarVector[F, FE]{*FE(new(F)).One()},
			FE(new(F)).One(),
			identity,
		).Prove[PE](transcript, *witness); err != nil {
			return nil, err
		}

		return transcript.Complete(), nil
	}()
	if err != nil {
		t.Fatal(err)
	}

	var verifier BatchVerifier[P, F]
	if err := NewIPStatementVerifier[P, F, FE](
		reduced,
		ScalarVector[F, FE]{*FE(new(F)).One()},
		FE(new(F)).One(),
		FE(new(F)).One(),
	).Verify[PE](&verifier, NewVerifierTranscript[P, F](context, proof)); err != nil {
		t.Fatal(err)
	}

	if !verifier.Verify[PE](generators) {
		t.Fatal("could not verify proof")
	}

}

func TestInnerProduct(t *testing.T) {
	t.Run("Constant", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testInnerProduct[curve25519.Point, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testInnerProduct[helioselene.HeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testInnerProduct[helioselene.SelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
	t.Run("VarTime", func(t *testing.T) {
		t.Run("Edwards25519", func(t *testing.T) {
			testInnerProduct[curve25519.VarTimePoint, curve25519.Scalar](t, rand.Reader)
		})
		t.Run("Helios", func(t *testing.T) {
			testInnerProduct[helioselene.VarTimeHeliosPoint, helioselene.HeliosScalar](t, rand.Reader)
		})
		t.Run("Selene", func(t *testing.T) {
			testInnerProduct[helioselene.VarTimeSelenePoint, helioselene.SeleneScalar](t, rand.Reader)
		})
	})
}

func testInnerProduct[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.Field[F]](t *testing.T, randomReader io.Reader) {
	// P = sum(g_bold * a, h_bold * b)
	generators, err := InsecureTestGenerator[P, F, PE, FE](32, randomReader)
	if err != nil {
		t.Fatal(err)
	}
	var verifier BatchVerifier[P, F]
	for i := 1; i <= 32; i++ {
		generators := generators.Reduce(i)
		g := generators.G
		if len(generators.GBold) != utils.NextPowerOfTwo(uint(i)) {
			t.FailNow()
		}

		gBold := PointVector[P, F, PE](slices.Clone(generators.GBold[:i]))
		hBold := PointVector[P, F, PE](slices.Clone(generators.HBold[:i]))

		a := make(ScalarVector[F, FE], i)
		b := make(ScalarVector[F, FE], i)
		for i := range a {
			curve.RandomScalar[F, FE](&a[i], randomReader)
		}
		for i := range b {
			curve.RandomScalar[F, FE](&b[i], randomReader)
		}

		p := PE(new(P)).Add(gBold.MultiExp[FE](new(P), a), hBold.MultiExp[FE](new(P), b))
		ip := a.InnerProduct(b)
		p = PE(p).Add(p, PE(new(P)).ScalarMult(&ip, &g))

		witness := NewIPWitness(a, b)

		context := [32]byte{}

		hBoldWeights := make(ScalarVector[F, FE], utils.NextPowerOfTwo(uint(i)))
		for i := range hBoldWeights {
			FE(&hBoldWeights[i]).One()
		}

		proof, err := func() ([]byte, error) {
			transcript := NewTranscript[P, F](context)
			if err := NewIPStatementProver[P, F, PE, FE](
				generators,
				hBoldWeights,
				FE(new(F)).One(),
				p,
			).Prove[PE](transcript, *witness); err != nil {
				return nil, err
			}

			return transcript.Complete(), nil
		}()
		if err != nil {
			t.Fatal(err)
		}

		verifier.Additional = append(verifier.Additional, multiexp.ScalarPointPair[P, F]{S: *FE(new(F)).One(), P: *p})

		if err := NewIPStatementVerifier[P, F, FE](
			generators,
			hBoldWeights,
			FE(new(F)).One(),
			FE(new(F)).One(),
		).Verify[PE](&verifier, NewVerifierTranscript[P, F](context, proof)); err != nil {
			t.Fatal(err)
		}
	}

	if !verifier.Verify[PE](generators) {
		t.Fatal("could not verify proofs")
	}
}
