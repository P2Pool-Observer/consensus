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
	products := []curve25519.Scalar{
		*ringct.AmountToScalar(new(curve25519.Scalar), 1),
		*ringct.AmountToScalar(new(curve25519.Scalar), 1<<len(challenges)),
	}

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

func PaddedPowerOfTwo[T int | uint64](i T) T {
	powerOfTwo := T(1)
	for powerOfTwo < i {
		powerOfTwo <<= 1
	}
	return powerOfTwo
}

var LogCommitmentBits = bits.Len(CommitmentBits)

// CalculateClawback Calculate the weight penalty for the Bulletproof(+).
//
// Bulletproofs(+) are logarithmically sized yet linearly timed. Evaluating by their size alone
// accordingly doesn't properly represent the burden of the proof. Monero 'claws back' some of
// the weight lost by using a proof smaller than it is fast to compensate for this.
//
// If the amount of outputs specified exceeds the maximum amount of outputs, the result for the
// maximum amount of outputs will be returned.
// https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/src/cryptonote_basic/cryptonote_format_utils.cpp#L106-L124
func CalculateClawback(plus bool, outputs int) (clawback, LRLen int) {
	nPaddedOutputs := 1
	for nPaddedOutputs < min(outputs, MaxCommitments) {
		LRLen++
		nPaddedOutputs <<= 1
	}
	LRLen += LogCommitmentBits

	if nPaddedOutputs > 2 {
		fields := 9
		if plus {
			fields = 6
		}

		base := ((fields + (2 * (LogCommitmentBits + 1))) * 32) / 2
		size := (fields + (2 * LRLen)) * 32
		clawback = ((base * nPaddedOutputs) - size) * 4 / 5
	}
	return clawback, LRLen
}
