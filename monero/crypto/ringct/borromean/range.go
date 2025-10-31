package borromean

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"

// Range A range proof premised on Borromean ring signatures.
type Range[T curve25519.PointOperations] struct {
	Signatures Signatures[T]
	// Commitments Bit commitments
	Commitments [Elements]curve25519.PublicKey[T]
}

func (s *Range[T]) Verify(commitment *curve25519.PublicKey[T]) bool {
	var sum curve25519.PublicKey[T]

	// initialize first sum element
	sum.P().Set(s.Commitments[0].P())
	for _, p := range s.Commitments[1:] {
		sum.Add(&sum, &p)
	}
	if sum.Equal(commitment) == 0 {
		return false
	}

	var commitmentsSubOne [Elements]curve25519.PublicKey[T]
	for i := range s.Commitments {
		commitmentsSubOne[i].Subtract(&s.Commitments[i], curve25519.FromPoint[T](generatorHPow2[i]))
	}

	return s.Signatures.Verify(&s.Commitments, &commitmentsSubOne)
}
