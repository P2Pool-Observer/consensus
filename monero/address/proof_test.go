package address

import (
	"crypto/rand"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

func TestProofs(t *testing.T) {
	addr, _, viewKey := randomAddress()

	var txId types.Hash
	_, _ = rand.Read(txId[:])

	txKey := crypto.PrivateKeyFromScalar(crypto.RandomScalar(new(edwards25519.Scalar), rand.Reader))

	t.Run("OutProofV1", func(t *testing.T) {
		proof := GetOutProofV1(addr, txId, txKey, "")
		_, ok := VerifyTxProof(proof, addr, txId, txKey.PublicKey(), "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
	t.Run("OutProofV2", func(t *testing.T) {
		proof := GetOutProofV2(addr, txId, txKey, "")
		_, ok := VerifyTxProof(proof, addr, txId, txKey.PublicKey(), "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
	t.Run("InProofV1", func(t *testing.T) {
		proof := GetInProofV1(addr, txId, viewKey, txKey.PublicKey(), "")
		_, ok := VerifyTxProof(proof, addr, txId, txKey.PublicKey(), "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
	t.Run("InProofV2", func(t *testing.T) {
		proof := GetInProofV2(addr, txId, viewKey, txKey.PublicKey(), "")
		_, ok := VerifyTxProof(proof, addr, txId, txKey.PublicKey(), "")
		if !ok {
			t.Error("Verify tx proof failed")
		}
	})
}
