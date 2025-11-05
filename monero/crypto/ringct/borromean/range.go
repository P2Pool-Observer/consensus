package borromean

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

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

func (s *Range[T]) BufferLength() int {
	const signatureSize = Elements*curve25519.PrivateKeySize*2 + curve25519.PrivateKeySize
	return signatureSize + Elements*curve25519.PublicKeySize
}

func (s *Range[T]) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf
	for _, scalar := range s.Signatures.S0 {
		buf = append(buf, scalar[:]...)
	}
	for _, scalar := range s.Signatures.S1 {
		buf = append(buf, scalar[:]...)
	}
	buf = append(buf, s.Signatures.EE.Bytes()...)

	for _, p := range s.Commitments {
		buf = append(buf, p.Slice()...)
	}

	return buf, nil
}

func (s *Range[T]) FromReader(reader utils.ReaderAndByteReader) (err error) {
	for i := range s.Signatures.S0 {
		if _, err = utils.ReadFullNoEscape(reader, s.Signatures.S0[i][:]); err != nil {
			return err
		}
	}
	for i := range s.Signatures.S1 {
		if _, err = utils.ReadFullNoEscape(reader, s.Signatures.S1[i][:]); err != nil {
			return err
		}
	}
	var k curve25519.PrivateKeyBytes
	if _, err = utils.ReadFullNoEscape(reader, k[:]); err != nil {
		return err
	}
	if _, err = s.Signatures.EE.SetCanonicalBytes(k[:]); err != nil {
		return err
	}
	var pub curve25519.PublicKeyBytes
	for i := range s.Commitments {
		if _, err = utils.ReadFullNoEscape(reader, pub[:]); err != nil {
			return err
		}
		if _, err = s.Commitments[i].SetBytes(pub[:]); err != nil {
			return err
		}
	}
	return nil
}
