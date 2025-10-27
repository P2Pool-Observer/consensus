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

// SignatureComm_2 Used in v1/v2 tx proofs
type SignatureComm_2[T curve25519.PointOperations] struct {

	// Fields used in V1/V2 proofs

	Message types.Hash
	// D Key Derivation
	D curve25519.PublicKey[T]
	// X Random Public Key
	X curve25519.PublicKey[T]
	// Y Random Public Derivation
	Y curve25519.PublicKey[T]

	// Fields used in V2 proofs

	// Separator Domain Separation
	Separator types.Hash
	// R Input public key
	R curve25519.PublicKey[T]
	A curve25519.PublicKey[T]
	B *curve25519.PublicKey[T]
}

func (s *SignatureComm_2[T]) Bytes(version uint8) []byte {
	buf := make([]byte, 0, types.HashSize*2+curve25519.PublicKeySize*6)
	buf = append(buf, s.Message[:]...)
	buf = append(buf, s.D.Slice()...)
	buf = append(buf, s.X.Slice()...)
	buf = append(buf, s.Y.Slice()...)
	if version == 1 {
		return buf
	}

	buf = append(buf, s.Separator[:]...)
	buf = append(buf, s.R.Slice()...)
	buf = append(buf, s.A.Slice()...)
	if s.B == nil {
		buf = append(buf, types.ZeroHash[:]...)
	} else {
		buf = append(buf, s.B.Slice()...)
	}
	return buf
}
