package clsag

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

type mode[T curve25519.PointOperations] interface {
	HashExtendD(DInvEight *curve25519.PublicKey[T], data []byte) []byte
	LoopConfiguration(data []byte, n int) (out []byte, start, end int, c1 curve25519.Scalar)
}

type modeVerify[T curve25519.PointOperations] struct {
	C1          curve25519.Scalar
	DSerialized curve25519.PublicKeyBytes
}

func (m modeVerify[T]) HashExtendD(DInvEight *curve25519.PublicKey[T], data []byte) []byte {
	data = append(data, m.DSerialized[:]...)
	return data
}

func (m modeVerify[T]) LoopConfiguration(data []byte, n int) (out []byte, start, end int, c1 curve25519.Scalar) {
	return data, 0, n, m.C1
}

type modeSign[T curve25519.PointOperations] struct {
	SignerIndex int
	A           curve25519.PublicKey[T]
	AH          curve25519.PublicKey[T]
}

func (m modeSign[T]) HashExtendD(DInvEight *curve25519.PublicKey[T], data []byte) []byte {
	data = append(data, DInvEight.Slice()...)
	return data
}

func (m modeSign[T]) LoopConfiguration(data []byte, n int) (out []byte, start, end int, c1 curve25519.Scalar) {
	data = append(data, m.A.Slice()...)
	data = append(data, m.AH.Slice()...)

	return data, m.SignerIndex + 1, m.SignerIndex + n, *crypto.ScalarDeriveLegacyNoAllocate(new(curve25519.Scalar), data)
}

var _ mode[curve25519.ConstantTimeOperations] = modeVerify[curve25519.ConstantTimeOperations]{}
var _ mode[curve25519.ConstantTimeOperations] = modeSign[curve25519.ConstantTimeOperations]{}
