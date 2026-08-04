package fcmp_plus_plus

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
	generalized_bulletproofs "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"
)

func HashGrow[
	P Point,
	S Scalar,
	PE curve.ExtraCurvePoint[P, S], SE curve.BasicField[S],
](
	generators *generalized_bulletproofs.Generators[P],
	existingHash *P,
	offset int,
	existingChildAtOffset *S,
	newChildren []S,
) *P {
	if len(newChildren) == 0 {
		return nil
	}

	pairs := make([]multiexp.ScalarPointPair[P, S, PE, SE], 0, len(newChildren))
	firstNew := newChildren[0]
	pairs = append(pairs, multiexp.ScalarPointPair[P, S, PE, SE]{
		S: *SE(new(S)).Subtract(&firstNew, existingChildAtOffset), P: *generators.GBold[offset],
	})
	for i := 1; i < len(newChildren); i++ {
		pairs = append(pairs, multiexp.ScalarPointPair[P, S, PE, SE]{
			S: newChildren[i], P: *generators.GBold[offset+i],
		})
	}

	return PE(new(P)).Add(existingHash, multiexp.MultiExp[P, S, PE, SE](new(P), pairs))
}

func HashTrim[
	P Point,
	S Scalar,
	PE curve.ExtraCurvePoint[P, S], SE curve.BasicField[S],
](
	generators *generalized_bulletproofs.Generators[P],
	existingHash *P,
	offset int,
	children []S,
	childToGrowBack *S,
) *P {
	pairs := make([]multiexp.ScalarPointPair[P, S, PE, SE], 0, len(children))
	for i, child := range children {
		if i == 0 {
			pairs = append(pairs, multiexp.ScalarPointPair[P, S, PE, SE]{
				S: *SE(new(S)).Subtract(&child, childToGrowBack), P: *generators.GBold[offset+i],
			})
		} else {
			pairs = append(pairs, multiexp.ScalarPointPair[P, S, PE, SE]{
				S: child, P: *generators.GBold[offset+i],
			})
		}
	}

	return PE(new(P)).Subtract(existingHash, multiexp.MultiExp[P, S, PE, SE](new(P), pairs))
}
