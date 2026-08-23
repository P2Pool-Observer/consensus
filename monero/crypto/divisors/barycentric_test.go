package divisors

import (
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/edwards25519/field"
	"git.gammaspectra.live/P2Pool/helioselene"
)

func TestUnivariatePoly_DivideXC(t *testing.T) {
	t.Run("Edwards25519", func(t *testing.T) {
		testUnivariatePoly_DivideXC[field.Element](t, rand.Reader)
	})
	t.Run("HelioSelene", func(t *testing.T) {
		testUnivariatePoly_DivideXC[helioselene.HelioSeleneField](t, rand.Reader)
	})
}

func testUnivariatePoly_DivideXC[F any, FE curve.Field[F]](t *testing.T, randomReader io.Reader) {
	t.Run("Zero", func(t *testing.T) {
		res, rem := UnivariatePoly[F]{}.DivideXC[FE](curve.RandomField[F, FE](new(F), randomReader))
		if len(res) != 0 {
			t.Fatal()
		}
		if FE(&rem).IsZero() == 0 {
			t.Fatal()
		}
	})
	t.Run("Single", func(t *testing.T) {
		c0 := curve.RandomField[F, FE](new(F), randomReader)
		res, rem := UnivariatePoly[F]{*c0}.DivideXC[FE](curve.RandomField[F, FE](new(F), randomReader))
		if len(res) != 0 {
			t.Fatal()
		}
		if FE(&rem).Equal(c0) == 0 {
			t.Fatal()
		}
	})

	for i := 2; i < 256; i++ {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			coeffs := make(UnivariatePoly[F], i)
			for i := range coeffs {
				curve.RandomField[F, FE](&coeffs[i], randomReader)
			}

			xCoeffs := slices.Clone(coeffs[:len(coeffs)-1])
			slices.Reverse(xCoeffs)

			poly := Poly[F]{
				ZeroCoefficient: coeffs[len(coeffs)-1],
				XCoefficients:   xCoeffs,
			}

			denom := curve.RandomField[F, FE](new(F), randomReader)
			coeffsDiv, coeffsRem := coeffs.DivideXC[FE](denom)
			polyDiv, polyRem := poly.DividePoly[FE](&Poly[F]{
				ZeroCoefficient: *denom,
				XCoefficients:   []F{*FE(new(F)).One()},
			})

			if FE(&coeffsDiv[len(coeffsDiv)-1]).Equal(&polyDiv.ZeroCoefficient) == 0 {
				t.Fatal()
			}
			lastCoeff := polyDiv.XCoefficients[len(polyDiv.XCoefficients)-1]
			polyDiv.XCoefficients = polyDiv.XCoefficients[:len(polyDiv.XCoefficients)-1]
			if FE(&lastCoeff).IsZero() == 0 {
				t.Fatal()
			}
			xCoeffsDiv := slices.Clone(coeffsDiv[:len(coeffsDiv)-1])
			slices.Reverse(xCoeffsDiv)
			if !curve.FieldSliceEqualsVarTime[F, FE](xCoeffsDiv, polyDiv.XCoefficients) {
				t.Fatal()
			}
			if len(polyDiv.YXCoefficients) != 0 {
				t.Fatal()
			}
			if len(polyDiv.YCoefficients) != 0 {
				t.Fatal()
			}
			if FE(&coeffsRem).Equal(&polyRem.ZeroCoefficient) == 0 {
				t.Fatal()
			}
			if len(polyRem.XCoefficients) != 0 {
				t.Fatal()
			}
			if len(polyRem.YXCoefficients) != 0 {
				t.Fatal()
			}
			if len(polyRem.YCoefficients) != 0 {
				t.Fatal()
			}

		})
	}
}

func TestInterpolation(t *testing.T) {
	t.Run("Edwards25519", func(t *testing.T) {
		testInterpolation[field.Element](t, rand.Reader)
	})
	t.Run("HelioSelene", func(t *testing.T) {
		testInterpolation[helioselene.HelioSeleneField](t, rand.Reader)
	})
}

func testInterpolation[F any, FE curve.Field[F]](t *testing.T, randomReader io.Reader) {

	for i := 2; i < 256; i++ {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			evals := make([]F, i)
			for j := range evals {
				curve.RandomField[F, FE](&evals[j], randomReader)
			}

			ip := NewInterpolator[F, FE](i - 1).Interpolate[FE](evals)
			slices.Reverse(ip)
			coeffs := UnivariatePoly[F](ip)

			for i, eval := range evals {
				res := coeffs.Eval[FE](curve.FieldFromUint64[F, FE](new(F), uint64(i)))
				if FE(&eval).Equal(&res) == 0 {
					t.Fatal("eval != coeffs.Eval")
				}
			}
		})
	}
}
