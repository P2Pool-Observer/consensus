package generalized_bulletproofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
)

type BatchVerifier[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.BasicField[F]] struct {
	// G Summed scalar for the G generator
	G F
	// H Summed scalar for the H generator
	H F

	// GBold Summed scalars for the G(bold) generators
	GBold []F
	// HBold Summed scalars for the H(bold) generators
	HBold []F

	// HSum The summed scalars for the sums of all H(bold) generators prior to the index.
	HSum []F

	Additional []multiexp.ScalarPointPair[P, F, PE, FE]
}

// Verify TODO: move this to a method once Go 1.27 is released
func (bv *BatchVerifier[P, F, PE, FE]) Verify(generators *Generators[P]) bool {
	type PointPair = multiexp.ScalarPointPair[P, F, PE, FE]
	pairs := make([]PointPair, 0, 2+len(bv.GBold)+len(bv.HBold)+len(bv.HSum)+len(bv.Additional))
	pairs = append(pairs, PointPair{S: bv.G, P: generators.G}, PointPair{S: bv.H, P: generators.H})
	for i := range bv.GBold {
		pairs = append(pairs, PointPair{S: bv.GBold[i], P: generators.GBold[i]})
	}
	for i := range bv.HBold {
		pairs = append(pairs, PointPair{S: bv.HBold[i], P: generators.HBold[i]})
	}
	for i := range min(len(bv.HSum), len(generators.HSum)) {
		pairs = append(pairs, PointPair{S: bv.HSum[i], P: generators.HSum[i]})
	}
	pairs = append(pairs, bv.Additional...)

	return PE(multiexp.MultiExp(new(P), pairs)).IsIdentity() == 1
}
