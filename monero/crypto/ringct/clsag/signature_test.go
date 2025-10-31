package clsag

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestCLSAG(t *testing.T) {

	t.Run("Constant", func(t *testing.T) {
		rng := crypto.NewDeterministicTestGenerator()
		testCLSAG[curve25519.ConstantTimeOperations](t, rng)
	})
	t.Run("VarTime", func(t *testing.T) {
		rng := crypto.NewDeterministicTestGenerator()
		testCLSAG[curve25519.VarTimeOperations](t, rng)
	})
}

const RingLength = 11
const Amount = 1337

func testCLSAG[T curve25519.PointOperations](t *testing.T, randomReader io.Reader) {
	for realIndex := range RingLength {
		t.Run(fmt.Sprintf("#%d", realIndex), func(t *testing.T) {
			var prefixHash = types.Hash{1}

			var secretKey, secretMask curve25519.Scalar

			decoys := ringct.Decoys[T]{
				SignerIndex: uint64(realIndex),
			}

			for i := range RingLength {

				var dest, mask curve25519.Scalar
				curve25519.RandomScalar(&dest, randomReader)
				curve25519.RandomScalar(&mask, randomReader)

				var amount uint64
				if i == realIndex {
					secretKey, secretMask = dest, mask
					amount = Amount
				} else {
					var buf [8]byte
					if _, err := io.ReadFull(randomReader, buf[:]); err != nil {
						t.Fatal(err)
					}
					amount = binary.LittleEndian.Uint64(buf[:])
				}
				decoys.Offsets = append(decoys.Offsets, uint64(i+1))
				decoys.Ring = append(decoys.Ring, [2]curve25519.PublicKey[T]{
					*new(curve25519.PublicKey[T]).ScalarBaseMult(&dest),
					*ringct.CalculateCommitment(new(curve25519.PublicKey[T]), ringct.Commitment{
						Mask:   mask,
						Amount: amount,
					}),
				})

			}

			var sumOutputs curve25519.Scalar
			curve25519.RandomScalar(&sumOutputs, randomReader)

			ctx, err := NewContext(decoys, ringct.Commitment{
				Mask:   secretMask,
				Amount: Amount,
			})
			if err != nil {
				t.Fatal(err)
			}

			keyPair := crypto.NewKeyPairFromPrivate[T](&secretKey)

			result, err := Sign(prefixHash, []Input[T]{
				{
					KeyPair: *keyPair,
					Context: *ctx,
				},
			}, &sumOutputs, randomReader)
			if err != nil {
				t.Fatalf("real %d: sign failed: %s", realIndex, err)
			}
			clsag := result[0].Signature
			pseudoOut := result[0].PseudoOut

			image := crypto.GetKeyImage(new(curve25519.PublicKey[T]), keyPair)

			if err := clsag.Verify(prefixHash, decoys.Ring, image, &pseudoOut); err != nil {
				t.Fatalf("real %d: verify failed: %s", realIndex, err)
			}
		})
	}
}
