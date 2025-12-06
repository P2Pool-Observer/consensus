package clsag

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
)

type Context[T curve25519.PointOperations] struct {
	Commitment ringct.LazyCommitment
	Decoys     ringct.Decoys[T]
}

func NewContext[T curve25519.PointOperations](decoys ringct.Decoys[T], commitment ringct.LazyCommitment) (*Context[T], error) {
	if len(decoys.Offsets) > 256 {
		return nil, ErrInvalidRing
	}

	if decoys.SignerRingMembers()[1].Equal(ringct.CalculateCommitment(new(curve25519.PublicKey[T]), commitment)) == 0 {
		return nil, ErrInvalidCommitment
	}

	return &Context[T]{
		Commitment: commitment,
		Decoys:     decoys,
	}, nil
}
