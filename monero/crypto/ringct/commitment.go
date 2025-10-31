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

func CalculateCommitment[T curve25519.PointOperations](out *curve25519.PublicKey[T], c Commitment) *curve25519.PublicKey[T] {
	Commit(out, c.Amount, &c.Mask)
	return out
}

// Commit generates C =aG + bH from b, a is mask
func Commit[T curve25519.PointOperations](dst *curve25519.PublicKey[T], amount uint64, mask *curve25519.Scalar) {

	var amountK curve25519.Scalar
	dst.DoubleScalarBaseMultPrecomputed(AmountToScalar(&amountK, amount), crypto.GeneratorH, mask)
}
