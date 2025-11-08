package bulletproofs

import (
	"math/bits"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
)

func saturatingSub(a, b uint64) uint64 {
	diff, borrow := bits.Sub64(a, b, 0)
	if borrow > 0 {
		diff = 0
	}
	return diff
}

// ChallengeProducts This has room for optimization worth investigating further.
// It currently takes an iterative approach. It can be optimized further via divide and conquer.
//
// Assume there are 4 challenges.
//
// Iterative approach (current):
//  1. Do the optimal multiplications across challenge column 0 and 1.
//  2. Do the optimal multiplications across that result and column 2.
//  3. Do the optimal multiplications across that result and column 3.
//
// Divide and conquer (worth investigating further):
//  1. Do the optimal multiplications across challenge column 0 and 1.
//  2. Do the optimal multiplications across challenge column 2 and 3.
//  3. Multiply both results together.
//
// When there are 4 challenges (n=16), the iterative approach does 28 multiplications versus divide and conquer's 24.
func ChallengeProducts(challenges [][2]curve25519.Scalar) []curve25519.Scalar {
	products := []curve25519.Scalar{*ringct.AmountToScalar(new(curve25519.Scalar), 1), *ringct.AmountToScalar(new(curve25519.Scalar), 1<<len(challenges))}

	if len(challenges) > 0 {
		products[0] = challenges[0][1]
		products[1] = challenges[0][0]

		products = append(products, make([]curve25519.Scalar, (1<<len(challenges))-2)...)

		for j, challenge := range challenges[1:] {
			slots := uint64((1 << (j + 2)) - 1)
			for slots > 0 {
				products[slots].Multiply(&products[slots/2], &challenge[0])
				products[slots-1].Multiply(&products[slots/2], &challenge[1])

				slots = saturatingSub(slots, 2)
			}
		}

		// Sanity check since if the above failed to populate, it'd be critical
		var zeroScalar curve25519.Scalar
		for _, product := range products {
			if product.Equal(&zeroScalar) == 1 {
				panic("challenge product cannot be zero")
			}
		}
	}
	return products
}

var amountScalarBit = [2]curve25519.Scalar{
	*(&curve25519.PrivateKeyBytes{0}).Scalar(),
	*(&curve25519.PrivateKeyBytes{1}).Scalar(),
}

func Decompose[T curve25519.PointOperations](amount uint64) (out ScalarVector[T]) {
	out = make(ScalarVector[T], 0, CommitmentBits)
	for range CommitmentBits {
		out = append(out, amountScalarBit[amount&1])
		amount >>= 1
	}
	return out
}
