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
