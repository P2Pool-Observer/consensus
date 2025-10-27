package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

// SignatureComm Used in normal message signatures
type SignatureComm[T curve25519.PointOperations] struct {
	Hash types.Hash
	Key  curve25519.PublicKey[T]
	Comm curve25519.PublicKey[T]
}

func (s *SignatureComm[T]) Bytes() []byte {
	var buf [types.HashSize + curve25519.PublicKeySize*2]byte

	copy(buf[:], s.Hash[:])
	copy(buf[types.HashSize:], s.Key.Slice())
	copy(buf[types.HashSize+curve25519.PublicKeySize:], s.Comm.Slice())
	return buf[:]
}
