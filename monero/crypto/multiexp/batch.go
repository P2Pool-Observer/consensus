package multiexp

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

type ScalarPointPair[T curve25519.PointOperations] struct {
	S curve25519.Scalar
	P curve25519.PublicKey[T]
}

type VerifierEntry[Id any, T curve25519.PointOperations] struct {
	Id    Id
	Pairs []ScalarPointPair[T]
}

type BatchVerifier[Id any, T curve25519.PointOperations] []VerifierEntry[Id, T]

func (v *BatchVerifier[Id, T]) Queue(id Id, pairs []ScalarPointPair[T], randomReader io.Reader) {

	// Define a unique scalar factor for this set of variables so individual items can't overlap
	var u curve25519.Scalar
	if len(*v) == 0 {
		u.One()
	} else {
		curve25519.RandomScalar(&u, randomReader)
	}

	for i := range pairs {
		pairs[i].S.Multiply(&pairs[i].S, &u)
	}

	*v = append(*v, VerifierEntry[Id, T]{
		Id:    id,
		Pairs: pairs,
	})
}

func (v *BatchVerifier[Id, T]) Verify() bool {
	return multiexp(new(curve25519.PublicKey[T]), flatten(*v)).IsIdentity() == 1
}

func flatten[Id any, T curve25519.PointOperations](entries []VerifierEntry[Id, T]) (pairs []ScalarPointPair[T]) {
	for _, e := range entries {
		pairs = append(pairs, e.Pairs...)
	}
	return pairs
}

func multiexp[T curve25519.PointOperations](out *curve25519.PublicKey[T], pairs []ScalarPointPair[T]) *curve25519.PublicKey[T] {
	if len(pairs) == 0 {
		return out.Identity()
	} else if len(pairs) == 1 {
		return out.ScalarMult(&pairs[0].S, &pairs[0].P)
	}

	scalars := make([]*curve25519.Scalar, 0, len(pairs))
	points := make([]*curve25519.PublicKey[T], 0, len(pairs))

	for _, pair := range pairs {
		scalars = append(scalars, &pair.S)
		points = append(points, &pair.P)
	}

	return out.MultiScalarMult(scalars, points)
}

//TODO: blame
