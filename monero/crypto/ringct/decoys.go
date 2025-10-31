package ringct

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"

type Decoys[T curve25519.PointOperations] struct {
	Offsets     []uint64
	SignerIndex uint64

	Ring [][2]curve25519.PublicKey[T]
}

func (d Decoys[T]) SignerRingMembers() *[2]curve25519.PublicKey[T] {
	return &d.Ring[d.SignerIndex]
}
