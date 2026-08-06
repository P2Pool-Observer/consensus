package generalized_bulletproofs

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func InsecureTestGenerator[P any, F any, PE curve.CurvePoint[P, F], FE curve.Field[F]](n int, randomReader io.Reader) (*Generators[P], error) {
	g := PE(new(P)).ScalarBaseMult(curve.RandomField[F, FE](new(F), randomReader))
	h := PE(new(P)).ScalarBaseMult(curve.RandomField[F, FE](new(F), randomReader))
	bold := func() []P {
		res := make([]P, 0, utils.NextPowerOfTwo(uint(n)))
		for range n {
			res = append(res, *PE(new(P)).ScalarBaseMult(curve.RandomField[F, FE](new(F), randomReader)))
		}
		return res
	}
	return NewGenerators[P, PE](g, h, bold(), bold())
}
