package address

import (
	"crypto/rand"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestProofs(t *testing.T) {
	addr, _, viewKey := randomAddress()

	var txId types.Hash
	_, _ = rand.Read(txId[:])

	txKey := crypto.RandomScalar(new(curve25519.Scalar), rand.Reader)
	txPubKey := new(curve25519.PublicKey[curve25519.ConstantTimeOperations]).ScalarBaseMult(txKey)

	t.Run("OutProofV1", func(t *testing.T) {
		proof := GetOutProof[curve25519.ConstantTimeOperations](addr, txId, txKey, "", 1)
		_, ok := VerifyTxProof(proof, addr, txId, txPubKey, "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
	t.Run("OutProofV2", func(t *testing.T) {
		proof := GetOutProof[curve25519.ConstantTimeOperations](addr, txId, txKey, "", 2)
		_, ok := VerifyTxProof(proof, addr, txId, txPubKey, "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
	t.Run("InProofV1", func(t *testing.T) {
		proof := GetInProof(addr, txId, viewKey, txPubKey, "", 1)
		_, ok := VerifyTxProof(proof, addr, txId, txPubKey, "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
	t.Run("InProofV2", func(t *testing.T) {
		proof := GetInProof(addr, txId, viewKey, txPubKey, "", 2)
		_, ok := VerifyTxProof(proof, addr, txId, txPubKey, "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
}
