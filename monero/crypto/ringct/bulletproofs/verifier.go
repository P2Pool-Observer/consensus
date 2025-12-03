package bulletproofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

type InternalBatchVerifier[T curve25519.PointOperations] struct {
	G     curve25519.Scalar
	H     curve25519.Scalar
	GBold []curve25519.Scalar
	HBold []curve25519.Scalar
	Other []ScalarPointPair[T]
}

type ScalarPointPair[T curve25519.PointOperations] struct {
	S curve25519.Scalar
	P curve25519.PublicKey[T]
}

func (ibv *InternalBatchVerifier[T]) Verify(G, H *curve25519.PublicKey[T], gen Generators) bool {
	capacity := 2 + len(ibv.GBold) + len(ibv.HBold) + len(ibv.Other)
	scalars := make([]*curve25519.Scalar, 0, capacity)
	points := make([]*curve25519.PublicKey[T], 0, capacity)

	scalars = append(scalars, &ibv.G)
	points = append(points, G)

	scalars = append(scalars, &ibv.H)
	points = append(points, H)

	for i := range ibv.GBold {
		scalars = append(scalars, &ibv.GBold[i])
		points = append(points, curve25519.FromPoint[T](gen.G[i]))
	}

	for i := range ibv.HBold {
		scalars = append(scalars, &ibv.HBold[i])
		points = append(points, curve25519.FromPoint[T](gen.H[i]))
	}

	for i := range ibv.Other {
		scalars = append(scalars, &ibv.Other[i].S)
		points = append(points, &ibv.Other[i].P)
	}

	return new(curve25519.PublicKey[T]).MultiScalarMult(scalars, points).IsIdentity() == 1
}
