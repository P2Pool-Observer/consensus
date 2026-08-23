package divisors

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
)

// ScalarDecomposition The decomposition of a scalar.
//
// The decomposition ($d$) of a scalar ($s$) has the following two properties:
//
// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i * 2^i = s$
// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i = \mathsf{NUM_BITS}$
type ScalarDecomposition[F any] struct {
	Scalar        F
	Decomposition []uint64
}

func NewScalarDecomposition[F any, FE curve.Field[F]](scalar *F) *ScalarDecomposition[F] {
	if FE(scalar).IsZero() == 1 {
		return nil
	}

	/*
	   We need the sum of the coefficients to equal F::NUM_BITS. The scalar's bits will be less than
	   F::NUM_BITS. Accordingly, we need to increment the sum of the coefficients without
	   incrementing the scalar represented. We do this by finding the highest non-0 coefficient,
	   decrementing it, and increasing the immediately less significant coefficient by 2. This
	   increases the sum of the coefficients by 1 (-1+2=1).
	*/

	numBits := FE(scalar).NumBits()

	// Obtain the bits of the scalar
	decomposition := make([]uint64, numBits)
	scalarBuf := FE(scalar).Bytes()

	for i := 0; i < numBits; i++ {
		bit := (scalarBuf[i/8] >> uint(i&7)) & 1
		decomposition[i] = uint64(bit)
	}

	// The following algorithm only works if the value of the scalar exceeds num_bits
	// If it isn't, we increase it by the modulus such that it does exceed num_bits
	{
		lessThanNumBits := 0
		for i := range numBits {
			lessThanNumBits |= FE(scalar).Equal(curve.FieldFromUint64[F, FE](new(F), uint64(i)))
		}

		decompositionOfModulus := make([]uint64, numBits)
		// Decompose negative one
		minusOneBuf := FE(FE(new(F)).Negate(FE(new(F)).One())).Bytes()

		for i := 0; i < numBits; i++ {
			bit := (minusOneBuf[i/8] >> uint(i&7)) & 1
			decompositionOfModulus[i] = uint64(bit)
		}

		// Increment it by one
		decompositionOfModulus[0]++

		// Add the decomposition onto the decomposition of the modulus
		for i := range numBits {
			decomposition[i] = select64Bits(decomposition[i]+decompositionOfModulus[i], decomposition[i], lessThanNumBits)
		}
	}

	// Calculate the sum of the coefficients
	var sumOfCoefficients uint64
	for _, d := range decomposition {
		sumOfCoefficients += d
	}

	/*
	   Now, because we added a log2(k)-bit number to a k-bit number, we may have our sum of
	   coefficients be *too high*. We attempt to reduce the sum of the coefficients accordingly.

	   This algorithm is guaranteed to complete as expected. Take the sequence `222`. `222` becomes
	   `032` becomes `013`. Even if the next coefficient in the sequence is `2`, the third
	   coefficient will be reduced once and the next coefficient (`2`, increased to `3`) will only
	   be eligible for reduction once. This demonstrates, even for a worst case of log2(k) `2`s
	   followed by `1`s (as possible if the modulus is a Mersenne prime), the log2(k) `2`s can be
	   reduced as necessary so long as there is a single coefficient after (requiring the entire
	   sequence be at least of length log2(k) + 1). For a 2-bit number, log2(k) + 1 == 2, so this
	   holds for any odd prime field.

	   To fully type out the demonstration for the Mersenne prime 3, with scalar to encode 1 (the
	   highest value less than the number of bits):

	   10 - Little-endian bits of 1
	   21 - Little-endian bits of 1, plus the modulus
	   02 - After one reduction, where the sum of the coefficients does in fact equal 2 (the target)
	*/

	{
		log2NumBits := 0
		for (1 << log2NumBits) < numBits {
			log2NumBits++
		}

		for range log2NumBits {
			// If the sum of coefficients is the amount of bits, we're done
			done := equal64Bits(sumOfCoefficients, uint64(numBits))

			for i := range numBits - 1 {
				shouldAct := (1 - done) & equal64Bits(decomposition[i], 1)
				// Subtract 2 from this coefficient
				amountToSub := select64Bits(2, 0, shouldAct)
				decomposition[i] -= amountToSub
				// Add 1 to the next coefficient
				amountToAdd := select64Bits(1, 0, shouldAct)
				decomposition[i+1] += amountToAdd

				// Also update the sum of coefficients
				sumOfCoefficients -= select64Bits(1, 0, shouldAct)

				// If we updated the coefficients this loop iter, we're done for this loop iter
				done |= shouldAct
			}
		}
	}

	for range numBits {
		// If the sum of coefficients is the amount of bits, we're done
		done := equal64Bits(sumOfCoefficients, uint64(numBits))

		// Find the highest coefficient currently non-zero
		for i := len(decomposition) - 1; i >= 1; i-- {
			// If this is non-zero, we should decrement this coefficient if we haven't already
			// decremented a coefficient this round
			isNonZero := 1 - equal64Bits(decomposition[i], 0)
			shouldAct := (1 - done) & isNonZero

			// Update this coefficient and the prior coefficient
			amountToSub := select64Bits(1, 0, shouldAct)
			decomposition[i] -= amountToSub

			amountToAdd := select64Bits(2, 0, shouldAct)
			// i must be at least 1, so i - 1 will be at least 0 (meaning it's safe to index with)
			decomposition[i+1] += amountToAdd

			// Also update the sum of coefficients
			sumOfCoefficients += select64Bits(1, 0, shouldAct)

			// If we updated the coefficients this loop iter, we're done for this loop iter
			done |= shouldAct
		}
	}

	// TODO debug assert
	{
		var sum uint64
		for _, d := range decomposition {
			sum += d
		}
		if sum != uint64(numBits) {
			panic("bad decomposition sum")
		}
	}

	return &ScalarDecomposition[F]{
		Scalar:        *scalar,
		Decomposition: decomposition,
	}
}
