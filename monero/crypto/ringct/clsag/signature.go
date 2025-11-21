package clsag

import (
	"errors"
	"fmt"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

var ErrInvalidKey = errors.New("invalid CLSAG key")
var ErrInvalidRing = errors.New("invalid CLSAG ring")
var ErrInvalidS = errors.New("invalid CLSAG S")
var ErrInvalidD = errors.New("invalid CLSAG D")
var ErrInvalidC1 = errors.New("invalid CLSAG C1")
var ErrInvalidImage = errors.New("invalid CLSAG image")
var ErrInvalidCommitment = errors.New("invalid CLSAG commitment")

type Signature[T curve25519.PointOperations] struct {
	// D The difference of the commitment randomnesses, scaling the key image generator
	D curve25519.PublicKeyBytes

	// S The responses for each ring member
	S []curve25519.Scalar

	// C1 The first challenge in the ring
	C1 curve25519.Scalar
}

func (s *Signature[T]) BufferLength() int {
	return len(s.S)*curve25519.PrivateKeySize + curve25519.PrivateKeySize + curve25519.PublicKeySize
}

func (s *Signature[T]) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	data = preAllocatedBuf
	for i := range s.S {
		data = append(data, s.S[i].Bytes()...)
	}
	data = append(data, s.C1.Bytes()...)
	data = append(data, s.D.Slice()...)
	return data, nil
}

func (s *Signature[T]) FromReader(reader utils.ReaderAndByteReader, decoys int) (err error) {
	var sec curve25519.PrivateKeyBytes
	var scalar curve25519.Scalar
	for range decoys {
		if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
			return err
		}
		if _, err = scalar.SetCanonicalBytes(sec[:]); err != nil {
			return err
		}
		s.S = append(s.S, scalar)
	}
	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = s.C1.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}
	if _, err = utils.ReadFullNoEscape(reader, s.D[:]); err != nil {
		return err
	}
	return nil
}

type Input[T curve25519.PointOperations] struct {
	KeyPair crypto.KeyPair[T]
	Context Context[T]
}

type SignResult[T curve25519.PointOperations] struct {
	Signature Signature[T]
	PseudoOut curve25519.PublicKey[T]
}

// Sign CLSAG signatures for the provided inputs.
//
// Monero ensures the rerandomized input commitments have the same value as the outputs by
// checking `sum(rerandomized_input_commitments) - sum(output_commitments) == 0`. This requires
// not only the amounts balance, yet also
// `sum(input_commitment_masks) - sum(output_commitment_masks)`.
//
// Monero solves this by following the wallet protocol to determine each output commitment's
// randomness, then using random masks for all but the last input. The last input is
// rerandomized to the necessary mask for the equation to balance.
//
// Due to Monero having this behavior, it only makes sense to sign CLSAGs as a list, hence this
// API being the way it is.
//
// `inputs` is of the form (discrete logarithm of the key, context).
//
// `sum_outputs` is for the sum of the output commitments' masks.
func Sign[T curve25519.PointOperations](prefixHash types.Hash, inputs []Input[T], sumOutputs *curve25519.Scalar, randomReader io.Reader) (result []SignResult[T], err error) {

	// Create the key images
	keyImageGenerators := make([]curve25519.PublicKey[T], len(inputs))
	keyImages := make([]curve25519.PublicKey[T], len(inputs))

	for i, input := range inputs {
		key := input.Context.Decoys.SignerRingMembers()[0]

		// Check the key is consistent
		if key.Equal(&input.KeyPair.PublicKey) == 0 {
			return nil, ErrInvalidKey
		}

		// can't use crypto.GetKeyImage as we need to store the generator
		crypto.BiasedHashToPoint(&keyImageGenerators[i], key.Bytes())
		keyImages[i].ScalarMult(&input.KeyPair.PrivateKey, &keyImageGenerators[i])
	}

	result = make([]SignResult[T], 0, len(inputs))

	var mask, sumPseudoOuts, nonce curve25519.Scalar

	for i := range inputs {

		// If this is the last input, set the mask as described above
		if i == (len(inputs) - 1) {
			mask.Subtract(sumOutputs, &sumPseudoOuts)
		} else {
			curve25519.RandomScalar(&mask, randomReader)
			sumPseudoOuts.Add(&sumPseudoOuts, &mask)
		}

		curve25519.RandomScalar(&nonce, randomReader)

		incomplete, pseudoOut, keyChallenge, challengedMask := signCore(
			prefixHash,
			&keyImages[i],
			&inputs[i].Context,
			&mask,
			new(curve25519.PublicKey[T]).ScalarBaseMult(&nonce),
			new(curve25519.PublicKey[T]).ScalarMult(&nonce, &keyImageGenerators[i]),
			randomReader,
		)

		// Effectively r - c x, except c x is (c_p x) + (c_c z), where z is the delta between the
		// ring member's commitment and our pseudo-out commitment (which will only have a known
		// discrete log over G if the amounts cancel out)

		incomplete.S[inputs[i].Context.Decoys.SignerIndex] = *new(curve25519.Scalar).Subtract(
			&nonce,
			new(curve25519.Scalar).Add(
				new(curve25519.Scalar).Multiply(
					keyChallenge,
					&inputs[i].KeyPair.PrivateKey,
				),
				challengedMask,
			),
		)

		//TODO: zeroize keys?

		// debug
		if err = incomplete.Verify(prefixHash, inputs[i].Context.Decoys.Ring, &keyImages[i], pseudoOut); err != nil {
			return nil, fmt.Errorf("verify: %w", err)
		}

		result = append(result, SignResult[T]{
			Signature: incomplete,
			PseudoOut: *pseudoOut,
		})
	}

	return result, nil
}

func (s *Signature[T]) Verify(prefixHash types.Hash, ring ringct.CommitmentRing[T], I, pseudoOut *curve25519.PublicKey[T]) error {
	if len(ring) == 0 {
		return ErrInvalidRing
	}

	if len(ring) != len(s.S) {
		return ErrInvalidS
	}

	if I == nil || I.IsIdentity() == 1 || !I.IsTorsionFree() {
		return ErrInvalidImage
	}

	// straightD D without torsion
	var straightD curve25519.PublicKey[T]
	if _, err := straightD.SetBytes(s.D[:]); err != nil {
		return ErrInvalidD
	}
	straightD.MultByCofactor(&straightD)
	if straightD.IsIdentity() == 1 {
		return ErrInvalidD
	}

	_, c1 := core(prefixHash, ring, I, pseudoOut, &straightD, s.S, modeVerify[T]{
		C1:          s.C1,
		DSerialized: s.D,
	})

	if c1.Equal(&s.C1) == 0 {
		return ErrInvalidC1
	}

	return nil
}
