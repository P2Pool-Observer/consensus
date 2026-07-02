package multiexp

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
)

type ScalarPointPair[P any, S any, PE curve.ExtraCurvePoint[P, S], SE curve.Scalar[S]] struct {
	S S
	P P
}

type VerifierEntry[Id any, P any, S any, PE curve.ExtraCurvePoint[P, S], SE curve.Scalar[S]] struct {
	Id    Id
	Pairs []ScalarPointPair[P, S, PE, SE]
}

type BatchVerifier[Id any, P any, S any, PE curve.ExtraCurvePoint[P, S], SE curve.Scalar[S]] []VerifierEntry[Id, P, S, PE, SE]

func (v *BatchVerifier[Id, P, S, PE, SE]) Queue(id Id, pairs []ScalarPointPair[P, S, PE, SE], randomReader io.Reader) {

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

	*v = append(*v, VerifierEntry[Id, P, S, PE, SE]{
		Id:    id,
		Pairs: pairs,
	})
}

// BlameVarTime Perform a binary search to identify which statement does not equal 0, returning statementFailed false if all statements do
//
// Variable time
func (v *BatchVerifier[Id, P, S, PE, SE]) BlameVarTime() (id Id, statementFailed bool) {
	slice := *v
	for len(slice) > 1 {
		split := len(slice) / 2
		testSplit := slice[:split]
		if testSplit.Verify() {
			slice = slice[split:]
		} else {
			slice = slice[:split]
		}
	}

	if len(slice) > 0 {
		first := slice[0]
		if PE(multiexp[P, S, PE, SE](new(P), first.Pairs)).IsIdentity() == 0 {
			return first.Id, true
		}
	}
	// return zero Id and false
	return id, false
}

func (v *BatchVerifier[Id, P, S, PE, SE]) Verify() bool {
	return PE(multiexp(new(P), flatten(*v))).IsIdentity() == 1
}

func flatten[Id any, P any, S any, PE curve.ExtraCurvePoint[P, S], SE curve.Scalar[S]](entries []VerifierEntry[Id, P, S, PE, SE]) (pairs []ScalarPointPair[P, S, PE, SE]) {
	for _, e := range entries {
		pairs = append(pairs, e.Pairs...)
	}
	return pairs
}

func multiexp[P any, S any, PE curve.ExtraCurvePoint[P, S], SE curve.Scalar[S]](out *P, pairs []ScalarPointPair[P, S, PE, SE]) *P {
	if len(pairs) == 0 {
		return PE(out).Identity()
	} else if len(pairs) == 1 {
		return PE(out).ScalarMult(&pairs[0].S, &pairs[0].P)
	}

	scalars := make([]*S, 0, len(pairs))
	points := make([]*P, 0, len(pairs))

	for _, pair := range pairs {
		scalars = append(scalars, &pair.S)
		points = append(points, &pair.P)
	}

	return PE(out).MultiScalarMult(scalars, points)
}

//TODO: blame
