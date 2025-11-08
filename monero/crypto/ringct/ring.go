package ringct

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"

type Ring[T curve25519.PointOperations] []curve25519.PublicKey[T]

// Index Returns the index for the given pubkey it found
// Variable time
func (ring Ring[T]) Index(pub *curve25519.PublicKey[T]) int {
	for i := range ring {
		if ring[i].Equal(pub) == 1 {
			return i
		}
	}
	return -1
}

// CommitmentRing A ring of output key, commitment
type CommitmentRing[T curve25519.PointOperations] [][2]curve25519.PublicKey[T]

// IndexKey Returns the index for the given pubkey it found
// Variable time
func (ring CommitmentRing[T]) IndexKey(pub *curve25519.PublicKey[T]) int {
	for i := range ring {
		if ring[i][0].Equal(pub) == 1 {
			return i
		}
	}
	return -1
}

func (ring CommitmentRing[T]) Ring(preAllocated Ring[T]) (out Ring[T]) {
	out = preAllocated
	for i := range ring {
		out = append(out, ring[i][0])
	}
	return out
}
