package borromean

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

const Elements = 64

// Signatures 64 Borromean ring signatures, as needed for a 64-bit range proof.
type Signatures[T curve25519.PointOperations] struct {
	S0 [Elements]curve25519.UnreducedScalar
	S1 [Elements]curve25519.UnreducedScalar
	EE curve25519.Scalar
}

func (s *Signatures[T]) Verify(A, B *[Elements]curve25519.PublicKey[T]) bool {
	var LL, LV curve25519.PublicKey[T]
	var tmpScalar, LLScalar curve25519.Scalar

	var transcript [curve25519.PublicKeySize * Elements]byte

	for i := range Elements {
		LL.DoubleScalarBaseMult(&s.EE, &A[i], s.S0[i].ScalarVarTime(&tmpScalar))
		crypto.ScalarDeriveLegacyNoAllocate(&LLScalar, LL.Slice())
		LV.DoubleScalarBaseMult(&LLScalar, &B[i], s.S1[i].ScalarVarTime(&tmpScalar))

		copy(transcript[i*curve25519.PublicKeySize:], LV.Slice())
	}
	return crypto.ScalarDeriveLegacyNoAllocate(&tmpScalar, transcript[:]).Equal(&s.EE) == 1
}
