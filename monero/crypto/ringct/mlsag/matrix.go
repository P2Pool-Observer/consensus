package mlsag

import (
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

// MinRingSize Monero requires that there is more than one ring member for MLSAG signatures:
// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/src/ringct/rctSigs.cpp#L462
const MinRingSize = 2

// RingMatrix A vector of rings, forming a matrix, to verify the MLSAG with.
type RingMatrix[T curve25519.PointOperations] []ringct.Ring[T]

func (r RingMatrix[T]) MemberLen() int {
	return len(r[0])
}

var ErrInvalidRing = errors.New("invalid ring")

func NewRingMatrix[T curve25519.PointOperations](rings ...ringct.Ring[T]) (RingMatrix[T], error) {
	if len(rings) < MinRingSize {
		return nil, ErrInvalidRing
	}

	for _, member := range rings {
		if len(member) != len(rings[0]) {
			return nil, ErrInvalidRing
		}
	}

	return rings, nil
}

func NewRingMatrixFromSingle[T curve25519.PointOperations](ring ringct.CommitmentRing[T], pseudoOut *curve25519.PublicKey[T]) (RingMatrix[T], error) {
	matrix := make([]ringct.Ring[T], 0, len(ring))
	for _, member := range ring {
		matrix = append(matrix, ringct.Ring[T]{member[0], *new(curve25519.PublicKey[T]).Subtract(&member[1], pseudoOut)})
	}
	return NewRingMatrix(matrix...)
}

func NewRingMatrixFromAggregateRings[T curve25519.PointOperations](fee uint64, commitments []curve25519.PublicKey[T], rings ...ringct.CommitmentRing[T]) (RingMatrix[T], error) {
	var keyRing []ringct.Ring[T]
	var amountsRing ringct.Ring[T]
	var sumOut curve25519.PublicKey[T]

	// initialize
	sumOut.P().Set(edwards25519.NewIdentityPoint())

	for _, commitment := range commitments {
		sumOut.Add(&sumOut, &commitment)
	}
	sumOut.Add(&sumOut, ringct.CalculateFeeCommitment(new(curve25519.PublicKey[T]), fee))

	sumOut.Negate(&sumOut)

	for _, ring := range rings {
		if len(keyRing) == 0 {
			keyRing = make([]ringct.Ring[T], len(ring))
			amountsRing = make(ringct.Ring[T], len(ring))
			for i := range len(ring) {
				amountsRing[i] = sumOut
			}
		}

		if len(amountsRing) != len(ring) || len(ring) == 0 {
			// All the rings in an aggregate matrix must be the same length.
			return nil, ErrInvalidRing
		}

		for i, member := range ring {
			keyRing[i] = append(keyRing[i], member[0])
			amountsRing[i].Add(&amountsRing[i], &member[1])
		}
	}

	for i, commitment := range amountsRing {
		keyRing[i] = append(keyRing[i], commitment)
	}

	return NewRingMatrix(keyRing...)
}
