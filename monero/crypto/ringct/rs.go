package ringct

import (
	"encoding/hex"
	"errors"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

// RingSignature Implements Pre-RingCT Traceable Ring Signature
// This is used in SpendProof
type RingSignature[T curve25519.PointOperations] []crypto.Signature[T]

type RingSignatureComm[T curve25519.PointOperations] struct {
	PrefixHash types.Hash
	AB         [][2]curve25519.PublicKey[T]
}

func (comm RingSignatureComm[T]) Scalar(out *curve25519.Scalar) *curve25519.Scalar {
	buf := make([]byte, 0, types.HashSize+len(comm.AB)*curve25519.PublicKeySize*2)
	buf = append(buf, comm.PrefixHash[:]...)
	for _, ab := range comm.AB {
		buf = append(buf, ab[0].Bytes()...)
		buf = append(buf, ab[1].Bytes()...)
	}
	return crypto.ScalarDeriveLegacy(out, buf)
}

func (s *RingSignature[T]) MarshalJSON() ([]byte, error) {
	out := make([]byte, 1, 2+curve25519.PrivateKeySize*2*len(*s))
	out[0] = '"'
	for _, sig := range *s {
		out = hex.AppendEncode(out, sig.Bytes())
	}
	out = append(out, '"')
	return out, nil
}

func (s *RingSignature[T]) UnmarshalJSON(b []byte) error {
	if len(b) < 2 {
		return io.ErrUnexpectedEOF
	}

	buf := make([]byte, hex.DecodedLen(len(b)-2))

	_, err := hex.Decode(buf, b[1:len(buf)-1])
	if err != nil {
		return err
	}
	if len(buf)%(curve25519.PrivateKeySize*2) != 0 {
		return errors.New("invalid signatures length")
	}

	for i := 0; i < len(buf); i += curve25519.PrivateKeySize * 2 {
		if sig := crypto.NewSignatureFromBytes[T](buf[i : i+curve25519.PrivateKeySize*2]); sig != nil {
			*s = append(*s, *sig)
		} else {
			return errors.New("invalid signature")
		}
	}

	return nil
}

func (s *RingSignature[T]) BufferLength() (n int) {
	return curve25519.PrivateKeySize * 2 * len(*s)
}

func (s *RingSignature[T]) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf

	for _, sig := range *s {
		buf = append(buf, sig.Bytes()...)
	}

	return buf, nil
}

func (s *RingSignature[T]) FromReader(reader utils.ReaderAndByteReader, count int) (err error) {
	var buf [curve25519.PrivateKeySize * 2]byte
	for range count {
		if _, err = utils.ReadFullNoEscape(reader, buf[:]); err != nil {
			return err
		}

		sig := crypto.NewSignatureFromBytes[T](buf[:])
		if sig == nil {
			return errors.New("invalid signature")
		}

		*s = append(*s, *sig)
	}
	return nil
}

// Sign Equivalent to Monero's generate_ring_signature
func (s *RingSignature[T]) Sign(prefixHash types.Hash, ring Ring[T], keyPair *crypto.KeyPair[T], randomReader io.Reader) bool {
	if keyIndex := ring.Index(&keyPair.PublicKey); keyIndex == -1 {
		return false
	} else {
		keyImage := crypto.GetKeyImage(new(curve25519.PublicKey[T]), keyPair)
		return s.sign(prefixHash, ring, keyImage, &keyPair.PrivateKey, keyIndex, randomReader)
	}
}

func (s *RingSignature[T]) sign(prefixHash types.Hash, ring Ring[T], keyImage *curve25519.PublicKey[T], key *curve25519.Scalar, keyIndex int, randomReader io.Reader) bool {
	if len(ring) == 0 || keyIndex < 0 || keyIndex >= len(ring) {
		// no public keys defined
		return false
	}
	*s = make([]crypto.Signature[T], len(ring))

	buf := RingSignatureComm[T]{
		PrefixHash: prefixHash,
		AB:         make([][2]curve25519.PublicKey[T], len(ring)),
	}

	//precomputedImage := curve25519.NewGenerator(keyImage.P())

	var sum edwards25519.Scalar

	var tmpH2P curve25519.PublicKey[T]
	var k curve25519.Scalar

	for i, pub := range ring {
		if i == keyIndex {
			if curve25519.RandomScalar(&k, randomReader) == nil {
				panic("unreachable")
			}
			buf.AB[i][0].ScalarBaseMult(&k)
			crypto.BiasedHashToPoint(&tmpH2P, pub.Bytes())
			buf.AB[i][1].ScalarMult(&k, &tmpH2P)
		} else {
			sig := &(*s)[i]
			if curve25519.RandomScalar(&sig.C, randomReader) == nil {
				panic("unreachable")
			}
			if curve25519.RandomScalar(&sig.R, randomReader) == nil {
				panic("unreachable")
			}
			buf.AB[i][0].DoubleScalarBaseMult(&sig.C, &pub, &sig.R)
			crypto.BiasedHashToPoint(&tmpH2P, pub.Bytes())
			//buf.AB[i][1].DoubleScalarMultPrecomputedB(&sig.R, &tmpH2P, &sig.C, precomputedImage)
			buf.AB[i][1].DoubleScalarMult(&sig.R, &tmpH2P, &sig.C, keyImage)
			sum.Add(&sum, &sig.C)
		}
	}

	var result curve25519.Scalar
	buf.Scalar(&result)
	(*s)[keyIndex].C.Subtract(&result, &sum)

	(*s)[keyIndex].R.Subtract(&k, new(curve25519.Scalar).Multiply(&(*s)[keyIndex].C, key))

	return true
}

// Verify Equivalent to Monero's check_ring_signature
func (s *RingSignature[T]) Verify(prefixHash types.Hash, ring Ring[T], keyImage *curve25519.PublicKey[T]) bool {
	if !keyImage.IsTorsionFree() {
		return false
	}

	return s.verify(prefixHash, ring, keyImage)
}

func (s *RingSignature[T]) verify(prefixHash types.Hash, ring Ring[T], keyImage *curve25519.PublicKey[T]) bool {
	if len(*s) == 0 {
		return false
	}
	if len(*s) != len(ring) {
		return false
	}

	buf := RingSignatureComm[T]{
		PrefixHash: prefixHash,
		AB:         make([][2]curve25519.PublicKey[T], len(ring)),
	}

	//precomputedImage := curve25519.NewGenerator(keyImage.P())

	var sum, result edwards25519.Scalar

	var tmpH2P curve25519.PublicKey[T]
	for i, pub := range ring {
		/*
		   The traditional Schnorr signature is:
		     r = sample()
		     c = H(r G || m)
		     s = r - c x
		   Verified as:
		     s G + c A == R

		   Each ring member here performs a dual-Schnorr signature for:
		     s G + c A
		     s HtP(A) + c K
		   Where the transcript is pushed both these values, r G, r HtP(A) for the real spend.
		   This also serves as a DLEq proof between the key and the key image.

		   Checking sum(c) == H(transcript) acts a disjunction, where any one of the `c`s can be
		   modified to cause the intended sum, if and only if a corresponding `s` value is known.
		*/

		sig := &(*s)[i]
		buf.AB[i][0].DoubleScalarBaseMult(&sig.C, &pub, &sig.R)
		crypto.BiasedHashToPoint(&tmpH2P, pub.Bytes())
		//buf.AB[i][1].DoubleScalarMultPrecomputedB(&sig.R, &tmpH2P, &sig.C, precomputedImage)
		buf.AB[i][1].DoubleScalarMult(&sig.R, &tmpH2P, &sig.C, keyImage)
		sum.Add(&sum, &sig.C)
	}

	buf.Scalar(&result)
	return sum.Equal(&result) == 1
}
