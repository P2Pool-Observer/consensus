package generalized_bulletproofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
)

type PedersenCommitment[P any, F any] struct {
	// Value committed to.
	Value F
	// Mask blinding the value committed to.
	Mask F
}

func (c *PedersenCommitment[P, F]) Commit[PE curve.ExtraCurvePoint[P, F]](out, g, h *P) *P {
	// TODO: precomputed?
	return PE(out).DoubleScalarMult(&c.Value, g, &c.Mask, h)
}

type PedersenVectorCommitment[P any, F any] struct {
	// GValues Values committed to across the G(bold) generators.
	GValues []F
	// Mask blinding the value committed to.
	Mask F
}

func (c *PedersenVectorCommitment[P, F]) Commit[PE curve.ExtraCurvePoint[P, F]](out *P, gBold []P, h *P) *P {
	if len(gBold) < len(c.GValues) {
		return nil
	}
	terms := make([]multiexp.ScalarPointPair[P, F], 0, 1+len(c.GValues))
	terms = append(terms, multiexp.ScalarPointPair[P, F]{S: c.Mask, P: *h})
	for i := range c.GValues {
		terms = append(terms, multiexp.ScalarPointPair[P, F]{S: c.GValues[i], P: gBold[i]})
	}
	return multiexp.MultiExp[P, F, PE](out, terms)
}
