package generalized_bulletproofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
)

// PedersenCommitment TODO: move to method generic in Go 1.27
type PedersenCommitment[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.BasicField[F]] struct {
	// Value committed to.
	Value F
	// Mask blinding the value committed to.
	Mask F
}

func (c *PedersenCommitment[P, F, PE, FE]) Commit(out, g, h *P) *P {
	// TODO: precomputed?
	return PE(out).DoubleScalarMult(&c.Value, g, &c.Mask, h)
}

// PedersenVectorCommitment TODO: move to method generic in Go 1.27
type PedersenVectorCommitment[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.BasicField[F]] struct {
	// GValues Values committed to across the G(bold) generators.
	GValues []F
	// Mask blinding the value committed to.
	Mask F
}

func (c *PedersenVectorCommitment[P, F, PE, FE]) Commit(out *P, gBold []P, h *P) *P {
	if len(gBold) < len(c.GValues) {
		return nil
	}
	terms := make([]multiexp.ScalarPointPair[P, F, PE, FE], 0, 1+len(c.GValues))
	terms = append(terms, multiexp.ScalarPointPair[P, F, PE, FE]{S: c.Mask, P: *h})
	for i := range c.GValues {
		terms = append(terms, multiexp.ScalarPointPair[P, F, PE, FE]{S: c.GValues[i], P: gBold[i]})
	}
	return multiexp.MultiExp(out, terms)
}
