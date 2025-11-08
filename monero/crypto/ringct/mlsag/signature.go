package mlsag

import (
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// Signature Implements MLSAG linkable ring signature, as used in Monero.
// https://www.getmonero.org/resources/research-lab/pubs/MRL-0005.pdf
type Signature[T curve25519.PointOperations] struct {
	SS [][]curve25519.Scalar
	CC curve25519.Scalar
}

func (s *Signature[T]) BufferLength() int {
	n := curve25519.PrivateKeySize
	for i := range s.SS {
		n += curve25519.PrivateKeySize * len(s.SS[i])
	}
	return n
}

func (s *Signature[T]) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf
	for _, ss := range s.SS {
		for _, scalar := range ss {
			buf = append(buf, scalar.Bytes()...)
		}
	}
	buf = append(buf, s.CC.Bytes()...)
	return buf, nil
}

func (s *Signature[T]) FromReader(reader utils.ReaderAndByteReader, decoys, elements int) (err error) {
	var k curve25519.PrivateKeyBytes
	for range decoys {
		var ring []curve25519.Scalar
		for range elements {
			if _, err = utils.ReadFullNoEscape(reader, k[:]); err != nil {
				return err
			}
			var scalar curve25519.Scalar
			if _, err = scalar.SetCanonicalBytes(k[:]); err != nil {
				return err
			}
			ring = append(ring, scalar)
		}
		s.SS = append(s.SS, ring)
	}
	if _, err = utils.ReadFullNoEscape(reader, k[:]); err != nil {
		return err
	}

	if _, err = s.CC.SetCanonicalBytes(k[:]); err != nil {
		return err
	}
	return nil
}

var ErrInvalidAmountOfKeyImages = errors.New("invalid amount of key images")
var ErrInvalidSS = errors.New("invalid SS")
var ErrInvalidCC = errors.New("invalid CC")
var ErrInvalidKeyImage = errors.New("invalid key image")

func (s *Signature[T]) Verify(prefixHash types.Hash, ringMatrix RingMatrix[T], keyImages []curve25519.PublicKey[T]) error {
	// Mlsag allows for layers to not need linkability, hence they don't need key images
	// Monero requires that there is always only 1 non-linkable layer - the amount commitments.

	if ringMatrix.MemberLen() != (len(keyImages) + 1) {
		return ErrInvalidAmountOfKeyImages
	}

	buf := make([]byte, 0, types.HashSize+5*curve25519.PublicKeySize)
	buf = append(buf, prefixHash[:]...)

	if len(ringMatrix) != len(s.SS) {
		return ErrInvalidSS
	}

	ci := s.CC

	var L, R curve25519.PublicKey[T]

	for i := range len(ringMatrix) {
		ss := s.SS[i]
		var member ringct.Ring[T]
		if i == len(ringMatrix) {
			// empty for non-linkable layer
		} else {
			member = ringMatrix[i]
		}
		if len(ss) != len(member) {
			return ErrInvalidSS
		}
		for j, entry := range member {
			s := ss[j]

			L.DoubleScalarBaseMult(&ci, &entry, &s)

			memberBytes := entry.Bytes()

			buf = append(buf, memberBytes[:]...)
			buf = append(buf, L.Slice()...)

			// Not all dimensions need to be linkable, e.g. commitments, and only linkable layers need
			// to have key images.
			if j < len(keyImages) {
				ki := keyImages[j]

				if ki.IsIdentity() || !ki.IsTorsionFree() {
					return ErrInvalidKeyImage
				}

				R.DoubleScalarMult(&s, crypto.BiasedHashToPoint(new(curve25519.PublicKey[T]), memberBytes[:]), &ci, &ki)
				buf = append(buf, R.Slice()...)
			}
		}

		crypto.ScalarDeriveLegacy(&ci, buf)
		// keep the prefixHash in the buffer.
		buf = buf[:types.HashSize]
	}

	if ci.Equal(&s.CC) == 0 {
		return ErrInvalidCC
	}

	return nil
}
