package clsag

import (
	"crypto/subtle"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type sigData[T curve25519.PointOperations] struct {
	DInvEight curve25519.PublicKey[T]
	cMuP      curve25519.Scalar
	cMuC      curve25519.Scalar
}

// invEight The inverse of 8 over l, the prime factor of the order of Ed25519.
var invEight = new(curve25519.Scalar).Invert((&curve25519.PrivateKeyBytes{8}).Scalar())

// core Core of the CLSAG algorithm, applicable to both sign and verify with minimal differences
//
// Said differences are covered via the above Mode
func core[T curve25519.PointOperations, T2 mode[T]](prefixHash types.Hash, ring [][2]curve25519.PublicKey[T], I, pseudoOut, straightD *curve25519.PublicKey[T], s []curve25519.Scalar, aC1 T2) (_ sigData[T], c1 *curve25519.Scalar) {

	DInvEight := new(curve25519.PublicKey[T]).ScalarMult(invEight, straightD)

	data := make([]byte, 0, ((2*len(ring))+5)*curve25519.PublicKeySize)
	data = append(data, prefix[:]...)
	data = append(data, agg0[:]...)
	data = append(data, make([]byte, curve25519.PublicKeySize-(len(prefix)+len(agg0)))...)

	P := make([]curve25519.PublicKey[T], len(ring))
	C := make([]curve25519.PublicKey[T], len(ring))

	for i, member := range ring {
		P[i] = member[0]
		data = append(data, member[0].Slice()...)
	}
	for i, member := range ring {
		C[i].Subtract(&member[1], pseudoOut)
		data = append(data, member[1].Slice()...)
	}

	data = append(data, I.Slice()...)

	// todo: noescape?
	data = aC1.HashExtendD(DInvEight, data)
	data = append(data, pseudoOut.Slice()...)

	// mu_P with agg_0
	muP := crypto.ScalarDeriveLegacyNoAllocate(new(curve25519.Scalar), data)

	// mu_C with agg_1
	data[len(prefix)+len(agg0)-1] = '1'
	muC := crypto.ScalarDeriveLegacyNoAllocate(new(curve25519.Scalar), data)

	// Truncate it for the round transcript, altering the DST as needed
	data = data[:((2*len(ring))+1)*curve25519.PublicKeySize]
	copy(data[len(prefix):], round[:])

	// Unfortunately, it's I D pseudo_out instead of pseudo_out I D, meaning this needs to be
	// truncated just to add it back
	data = append(data, pseudoOut.Slice()...)
	data = append(data, prefixHash[:]...)

	var start, end int
	var c curve25519.Scalar

	data, start, end, c = aC1.LoopConfiguration(data, len(ring))

	c1 = new(curve25519.Scalar).Set(&c)

	var cP, cC curve25519.Scalar

	var L, PH, R curve25519.PublicKey[T]

	for j := start; j < end; j++ {
		i := j % len(ring)

		cP.Multiply(muP, &c)
		cC.Multiply(muC, &c)

		// (s_i * G) + (c_p * P_i) + (c_c * C_i)
		aC1.Loop0(&L, &s[i], &cP, &cC, &P[i], &C[i])

		crypto.BiasedHashToPoint(&PH, P[i].Slice())

		// (c_p * I) + (c_c * D) + (s_i * PH)

		aC1.Loop1(&R, &s[i], &cP, &cC, I, straightD, &PH)

		data = data[:((2*len(ring))+3)*curve25519.PublicKeySize]
		data = append(data, L.Slice()...)
		data = append(data, R.Slice()...)
		crypto.ScalarDeriveLegacyNoAllocate(&c, data)

		// This will only execute once and shouldn't need to be constant time. Making it constant time
		// removes the risk of branch prediction creating timing differences depending on ring index however
		// TODO: add constant set on upstream
		if subtle.ConstantTimeEq(int32(i), int32(len(ring)-1)) == 1 {
			c1.Set(&c)
		} else {
			c1.Set(c1)
		}
	}

	// This first tuple is needed to continue signing, the latter is the c to be tested/worked with
	return sigData[T]{
		DInvEight: *DInvEight,
		cMuP:      *new(curve25519.Scalar).Multiply(&c, muP),
		cMuC:      *new(curve25519.Scalar).Multiply(&c, muC),
	}, c1
}

const prefix = "CLSAG_"
const agg0 = "agg_0"
const round = "round"

func signCore[T curve25519.PointOperations](prefixHash types.Hash, I *curve25519.PublicKey[T], input *Context[T], mask *curve25519.Scalar, A, AH *curve25519.PublicKey[T], randomReader io.Reader) (incomplete Signature[T], pseudoOut *curve25519.PublicKey[T], keyChallenge, challengedMask *curve25519.Scalar) {
	signerIndex := input.Decoys.SignerIndex

	pseudoOut = ringct.CalculateCommitment(new(curve25519.PublicKey[T]), ringct.Commitment{
		Mask:   *mask,
		Amount: input.Commitment.Amount,
	})

	maskDelta := new(curve25519.Scalar).Subtract(&input.Commitment.Mask, mask)

	H := crypto.BiasedHashToPoint(new(curve25519.PublicKey[T]), input.Decoys.Ring[signerIndex][0].Slice())
	D := new(curve25519.PublicKey[T]).ScalarMult(maskDelta, H)

	s := make([]curve25519.Scalar, len(input.Decoys.Ring))
	for i := range s {
		curve25519.RandomScalar(&s[i], randomReader)
	}
	data, c1 := core(prefixHash, input.Decoys.Ring, I, pseudoOut, D, s, modeSign[T]{
		SignerIndex: int(signerIndex),
		A:           *A,
		AH:          *AH,
	})

	return Signature[T]{
		D:  data.DInvEight.Bytes(),
		S:  s,
		C1: *c1,
	}, pseudoOut, &data.cMuP, new(curve25519.Scalar).Multiply(&data.cMuC, maskDelta)
}
