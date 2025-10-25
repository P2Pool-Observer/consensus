package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

// SignatureComm Used in normal message signatures
type SignatureComm struct {
	Hash types.Hash
	Key  PublicKeyPoint
	Comm PublicKeyPoint
}

func (s *SignatureComm) Bytes() []byte {
	var buf [types.HashSize + PublicKeySize*2]byte

	copy(buf[:], s.Hash[:])
	copy(buf[types.HashSize:], s.Key.AsSlice()[:])
	copy(buf[types.HashSize+PublicKeySize:], s.Comm.AsSlice()[:])
	return buf[:]
}

// SignatureComm_2 Used in v1/v2 tx proofs
type SignatureComm_2 struct {
	Message types.Hash
	// D Key Derivation
	D PublicKeyPoint
	// X Random Public Key
	X PublicKeyPoint
	// Y Random Public Derivation
	Y PublicKeyPoint
	// Separator Domain Separation
	Separator types.Hash
	// R Input public key
	R PublicKeyPoint
	A PublicKeyPoint
	B *PublicKeyPoint
}

func (s *SignatureComm_2) Bytes() []byte {
	buf := make([]byte, 0, types.HashSize*2+PublicKeySize*6)
	buf = append(buf, s.Message[:]...)
	buf = append(buf, s.D.AsSlice()...)
	buf = append(buf, s.X.AsSlice()...)
	buf = append(buf, s.Y.AsSlice()...)
	buf = append(buf, s.Separator[:]...)
	buf = append(buf, s.R.AsSlice()...)
	buf = append(buf, s.A.AsSlice()...)
	if s.B == nil {
		buf = append(buf, types.ZeroHash[:]...)
	} else {
		buf = append(buf, s.B.AsSlice()...)
	}
	return buf
}

// SignatureComm_2_V1 Used in v1 tx proofs
type SignatureComm_2_V1 struct {
	Message types.Hash
	// D Key Derivation
	D PublicKeyPoint
	// X Random Public Key
	X PublicKeyPoint
	// Y Random Public Derivation
	Y PublicKeyPoint
}

func (s *SignatureComm_2_V1) Bytes() []byte {
	buf := make([]byte, 0, types.HashSize+PublicKeySize*3)
	buf = append(buf, s.Message[:]...)
	buf = append(buf, s.D.AsSlice()...)
	buf = append(buf, s.X.AsSlice()...)
	buf = append(buf, s.Y.AsSlice()...)
	return buf
}
