package ringct

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

type Commitment struct {
	Mask   curve25519.Scalar
	Amount uint64
}

// ZeroCommitment A commitment to zero, defined with a mask of 1 (as to not be the identity).
var ZeroCommitment = Commitment{
	Mask:   *(&curve25519.PrivateKeyBytes{1}).Scalar(),
	Amount: 0,
}

func CalculateFeeCommitment[T curve25519.PointOperations](out *curve25519.PublicKey[T], fee uint64) *curve25519.PublicKey[T] {
	return out.ScalarMultPrecomputed(AmountToScalar(new(curve25519.Scalar), fee), crypto.GeneratorH)
}

func CalculateCommitment[T curve25519.PointOperations](out *curve25519.PublicKey[T], c Commitment) *curve25519.PublicKey[T] {
	Commit(out, c.Amount, &c.Mask)
	return out
}

// coinbaseAmountBlindingFactor precompute coinbase blinding factor scalar multiplication
var coinbaseAmountBlindingFactor = new(curve25519.Point).ScalarBaseMult((&curve25519.PrivateKeyBytes{1}).Scalar())

// CalculateCommitmentCoinbase Specialized implementation with baked in blinding factor
// this is faster than CalculateCommitment, but is specific only for coinbase (as it uses a fixed amount blinding key)
func CalculateCommitmentCoinbase[T curve25519.PointOperations](out *curve25519.PublicKey[T], amount uint64) *curve25519.PublicKey[T] {
	var amountK curve25519.Scalar
	out.ScalarMultPrecomputed(AmountToScalar(&amountK, amount), crypto.GeneratorH)
	return out.Add(out, curve25519.FromPoint[T](coinbaseAmountBlindingFactor))
}

// Commit generates C =aG + bH from b, a is mask
func Commit[T curve25519.PointOperations](dst *curve25519.PublicKey[T], amount uint64, mask *curve25519.Scalar) {

	var amountK curve25519.Scalar
	dst.DoubleScalarBaseMultPrecomputed(AmountToScalar(&amountK, amount), crypto.GeneratorH, mask)
}
