package clsag

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

type mode[T curve25519.PointOperations] interface {
	HashExtendD(DInvEight *curve25519.PublicKey[T], data []byte) []byte
	LoopConfiguration(data []byte, n int) (out []byte, start, end int, c1 curve25519.Scalar)
	Loop0(out *curve25519.PublicKey[T], s, cP, cC *curve25519.Scalar, P, C *curve25519.PublicKey[T]) *curve25519.PublicKey[T]
	Loop1(out *curve25519.PublicKey[T], s, cP, cC *curve25519.Scalar, I, straightD, PH *curve25519.PublicKey[T]) *curve25519.PublicKey[T]
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

func (m modeVerify[T]) Loop0(out *curve25519.PublicKey[T], s, cP, cC *curve25519.Scalar, P, C *curve25519.PublicKey[T]) *curve25519.PublicKey[T] {
	// (s_i * G) + (c_p * P_i) + (c_c * C_i)
	// TODO: vartime
	var scalars = [3]*curve25519.Scalar{s, cP, cC}
	var points = [3]*curve25519.PublicKey[T]{curve25519.FromPoint[T](crypto.GeneratorG.Point), P, C}
	return out.MultiScalarMult(scalars[:], points[:])
}

func (m modeVerify[T]) Loop1(out *curve25519.PublicKey[T], s, cP, cC *curve25519.Scalar, I, straightD, PH *curve25519.PublicKey[T]) *curve25519.PublicKey[T] {
	// (c_p * I) + (c_c * D) + (s_i * PH)
	// TODO: vartime
	var scalars = [3]*curve25519.Scalar{cP, cC, s}
	var points = [3]*curve25519.PublicKey[T]{I, straightD, PH}
	return out.MultiScalarMult(scalars[:], points[:])
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

func (m modeSign[T]) Loop0(out *curve25519.PublicKey[T], s, cP, cC *curve25519.Scalar, P, C *curve25519.PublicKey[T]) *curve25519.PublicKey[T] {
	// (s_i * G) + (c_p * P_i) + (c_c * C_i)
	var scalars = [3]*curve25519.Scalar{s, cP, cC}
	var points = [3]*curve25519.PublicKey[T]{curve25519.FromPoint[T](crypto.GeneratorG.Point), P, C}
	return out.MultiScalarMult(scalars[:], points[:])
}

func (m modeSign[T]) Loop1(out *curve25519.PublicKey[T], s, cP, cC *curve25519.Scalar, I, straightD, PH *curve25519.PublicKey[T]) *curve25519.PublicKey[T] {
	// (c_p * I) + (c_c * D) + (s_i * PH)
	var scalars = [3]*curve25519.Scalar{cP, cC, s}
	var points = [3]*curve25519.PublicKey[T]{I, straightD, PH}
	return out.MultiScalarMult(scalars[:], points[:])
}

var _ mode[curve25519.ConstantTimeOperations] = modeVerify[curve25519.ConstantTimeOperations]{}
var _ mode[curve25519.ConstantTimeOperations] = modeSign[curve25519.ConstantTimeOperations]{}
