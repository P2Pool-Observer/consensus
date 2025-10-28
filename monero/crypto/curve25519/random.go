package curve25519

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// RandomScalar Equivalent to Monero's random32_unbiased / random_scalar
func RandomScalar(k *Scalar, r io.Reader) *Scalar {
	var buf [PrivateKeySize]byte
	for {
		if _, err := utils.ReadNoEscape(r, buf[:]); err != nil {
			return nil
		}

		if !ScalarIsLimit32(buf) {
			continue
		}
		BytesToScalar32(k, buf)

		if k.Equal(zeroScalar) == 0 {
			return k
		}
	}
}

// RandomPoint Equivalent to Monero's rctOps::pkGen
// Use for testing
func RandomPoint[T PointOperations](k *PublicKey[T], r io.Reader) *PublicKey[T] {
	return k.ScalarBaseMult(RandomScalar(new(Scalar), r))
}
