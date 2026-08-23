package multiexp

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
)

type ScalarPointPair[P any, S any] struct {
	S S
	P P
}

type VerifierEntry[Id any, P any, S any] struct {
	Id    Id
	Pairs []ScalarPointPair[P, S]
}

type BatchVerifier[Id any, P any, S any] []VerifierEntry[Id, P, S]

func (v *BatchVerifier[Id, P, S]) Queue[SE curve.Scalar[S]](id Id, pairs []ScalarPointPair[P, S], randomReader io.Reader) {

	// Define a unique scalar factor for this set of variables so individual items can't overlap
	var u S
	if len(*v) == 0 {
		SE(&u).One()
	} else {
		curve.RandomScalar[S, SE](&u, randomReader)
	}

	for i := range pairs {
		SE(&pairs[i].S).Multiply(&pairs[i].S, &u)
	}

	*v = append(*v, VerifierEntry[Id, P, S]{
		Id:    id,
		Pairs: pairs,
	})
}

// BlameVarTime Perform a binary search to identify which statement does not equal 0, returning statementFailed false if all statements do
//
// Variable time
func (v *BatchVerifier[Id, P, S]) BlameVarTime[PE curve.ExtraCurvePoint[P, S]]() (id Id, statementFailed bool) {
	slice := *v
	for len(slice) > 1 {
		split := len(slice) / 2
		testSplit := slice[:split]
		if testSplit.Verify[PE]() {
			slice = slice[split:]
		} else {
			slice = slice[:split]
		}
	}

	if len(slice) > 0 {
		first := slice[0]
		if PE(MultiExp[P, S, PE](new(P), first.Pairs)).IsIdentity() == 0 {
			return first.Id, true
		}
	}
	// return zero Id and false
	return id, false
}

func (v *BatchVerifier[Id, P, S]) Verify[PE curve.ExtraCurvePoint[P, S]]() bool {
	return PE(MultiExp[P, S, PE](new(P), flatten(*v))).IsIdentity() == 1
}

func flatten[Id any, P any, S any](entries []VerifierEntry[Id, P, S]) (pairs []ScalarPointPair[P, S]) {
	for _, e := range entries {
		pairs = append(pairs, e.Pairs...)
	}
	return pairs
}

func MultiExp[P any, S any, PE curve.ExtraCurvePoint[P, S]](out *P, pairs []ScalarPointPair[P, S]) *P {
	if len(pairs) == 0 {
		return PE(out).Identity()
	} else if len(pairs) == 1 {
		return PE(out).ScalarMult(&pairs[0].S, &pairs[0].P)
	} else if len(pairs) == 2 {
		return PE(out).DoubleScalarMult(&pairs[0].S, &pairs[0].P, &pairs[1].S, &pairs[1].P)
	}

	scalars := make([]*S, 0, len(pairs))
	points := make([]*P, 0, len(pairs))

	for i := range pairs {
		scalars = append(scalars, &pairs[i].S)
		points = append(points, &pairs[i].P)
	}

	return PE(out).MultiScalarMult(scalars, points)
}
