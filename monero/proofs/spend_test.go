package proofs

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestSpendProof(t *testing.T) {
	const decoys = 15
	const n = 10

	t.Run("Constant", func(t *testing.T) {
		if err := testSpendProof[curve25519.ConstantTimeOperations](decoys, n, 1, rand.Reader); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Variable", func(t *testing.T) {
		if err := testSpendProof[curve25519.VarTimeOperations](decoys, n, 1, rand.Reader); err != nil {
			t.Fatal(err)
		}
	})
}

func testSpendProof[T curve25519.PointOperations](decoys, n, version int, randomReader io.Reader) error {
	var keyPairs []*crypto.KeyPair[T]
	var rings []ringct.Ring[T]

	for i := range n {
		keyPair := crypto.NewKeyPairFromPrivate[T](curve25519.RandomScalar(new(curve25519.Scalar), randomReader))
		rings = append(rings, make([]curve25519.PublicKey[T], 0, decoys+1))
		keyIndex := i
		for j := range decoys + 1 {
			// pick secret index
			if j == keyIndex {
				rings[i] = append(rings[i], keyPair.PublicKey)
			} else {
				rings[i] = append(rings[i], *new(curve25519.PublicKey[T]).ScalarBaseMult(curve25519.RandomScalar(new(curve25519.Scalar), randomReader)))
			}
		}
		keyPairs = append(keyPairs, keyPair)
	}

	var txId types.Hash
	_, _ = randomReader.Read(txId[:])

	proof, err := GetSpendProof[T](txId, "", uint8(version), keyPairs, rings, randomReader)
	if err != nil {
		return err
	}

	var keyImages []curve25519.PublicKey[T]

	for _, keyPair := range keyPairs {
		keyImages = append(keyImages, *crypto.GetKeyImage(new(curve25519.PublicKey[T]), keyPair))
	}

	if !proof.Verify(TxPrefixHash(txId, ""), keyImages, rings) {
		return errors.New("proof verification failed")
	}

	proof2, err := NewSpendProofFromString[T](proof.String())
	if err != nil {
		return err
	}

	if !proof2.Verify(TxPrefixHash(txId, ""), keyImages, rings) {
		return errors.New("proof verification failed")
	}

	return nil
}
