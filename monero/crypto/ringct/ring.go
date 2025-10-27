package ringct

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

type RingSignature[T curve25519.PointOperations] struct {
	Ring       []curve25519.PublicKey[T]
	Signatures []crypto.Signature[T]
}

type RingSignatureComm[T curve25519.PointOperations] struct {
	PrefixHash types.Hash
	AB         [][2]curve25519.PublicKey[T]
}

func (comm RingSignatureComm[T]) Bytes() []byte {
	buf := make([]byte, 0, types.HashSize+len(comm.AB)*curve25519.PublicKeySize*2)
	buf = append(buf, comm.PrefixHash[:]...)
	for _, ab := range comm.AB {
		buf = append(buf, ab[0].Slice()...)
		buf = append(buf, ab[1].Slice()...)
	}
	return buf
}

// Sign Equivalent to Monero's generate_ring_signature
func (s *RingSignature[T]) Sign(prefixHash types.Hash, keyPair *crypto.KeyPair[T], keyIndex int, randomReader io.Reader) {
	if len(s.Ring) == 0 || keyIndex < 0 || keyIndex >= len(s.Ring) {
		panic("no public keys defined")
	}
	s.Signatures = make([]crypto.Signature[T], len(s.Ring))

	buf := RingSignatureComm[T]{
		PrefixHash: prefixHash,
		AB:         make([][2]curve25519.PublicKey[T], len(s.Ring)),
	}

	keyImage := crypto.GetKeyImage(new(curve25519.PublicKey[T]), keyPair)

	precomputedImage := curve25519.NewGenerator(keyImage.P())

	var sum edwards25519.Scalar

	var tmpH2P curve25519.PublicKey[T]
	var k curve25519.Scalar

	for i, pub := range s.Ring {
		if i == keyIndex {
			if crypto.RandomScalar(&k, randomReader) == nil {
				panic("unreachable")
			}
			buf.AB[i][0].ScalarBaseMult(&k)
			crypto.BiasedHashToPoint(&tmpH2P, pub.Slice())
			buf.AB[i][1].ScalarMult(&k, &tmpH2P)
		} else {
			sig := &s.Signatures[i]
			if crypto.RandomScalar(&sig.C, randomReader) == nil {
				panic("unreachable")
			}
			if crypto.RandomScalar(&sig.R, randomReader) == nil {
				panic("unreachable")
			}
			buf.AB[i][0].DoubleScalarBaseMult(&sig.C, &pub, &sig.R)
			crypto.BiasedHashToPoint(&tmpH2P, pub.Slice())
			buf.AB[i][1].DoubleScalarMultPrecomputedB(&sig.R, &tmpH2P, &sig.C, precomputedImage)
			sum.Add(&sum, &sig.C)
		}
	}

	var result curve25519.Scalar
	crypto.ScalarDeriveLegacyNoAllocate(&result, buf.Bytes())
	s.Signatures[keyIndex].C.Subtract(&result, &sum)

	s.Signatures[keyIndex].R.Subtract(&k, new(curve25519.Scalar).Multiply(&s.Signatures[keyIndex].C, &keyPair.PrivateKey))
}

// Verify Equivalent to Monero's check_ring_signature
func (s *RingSignature[T]) Verify(prefixHash types.Hash, keyImage *curve25519.PublicKey[T]) bool {
	if len(s.Signatures) == 0 {
		return false
	}
	if len(s.Signatures) != len(s.Ring) {
		return false
	}

	if !keyImage.IsTorsionFree() {
		return false
	}

	buf := RingSignatureComm[T]{
		PrefixHash: prefixHash,
		AB:         make([][2]curve25519.PublicKey[T], len(s.Ring)),
	}

	precomputedImage := curve25519.NewGenerator(keyImage.P())

	var sum, result edwards25519.Scalar

	var tmpH2P curve25519.PublicKey[T]
	for i, pub := range s.Ring {
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

		sig := &s.Signatures[i]
		buf.AB[i][0].DoubleScalarBaseMult(&sig.C, &pub, &sig.R)
		crypto.BiasedHashToPoint(&tmpH2P, pub.Slice())
		buf.AB[i][1].DoubleScalarMultPrecomputedB(&sig.R, &tmpH2P, &sig.C, precomputedImage)
		sum.Add(&sum, &sig.C)
	}

	return sum.Equal(crypto.ScalarDeriveLegacyNoAllocate(&result, buf.Bytes())) == 1
}
