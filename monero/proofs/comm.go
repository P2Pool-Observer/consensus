package proofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

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
	buf = append(buf, s.D.Bytes()...)
	buf = append(buf, s.X.Bytes()...)
	buf = append(buf, s.Y.Bytes()...)
	if version == 1 {
		return buf
	}

	buf = append(buf, s.Separator[:]...)
	buf = append(buf, s.R.Bytes()...)
	buf = append(buf, s.A.Bytes()...)
	if s.B == nil {
		buf = append(buf, types.ZeroHash[:]...)
	} else {
		buf = append(buf, s.B.Bytes()...)
	}
	return buf
}
