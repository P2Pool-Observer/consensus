package wallet

import (
	"crypto/rand"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestCarrotSpendWallet_Match(t *testing.T) {
	var masterSecret types.Hash
	_, _ = rand.Read(masterSecret[:])

	wallet, err := NewCarrotSpendWalletFromMasterSecret[curve25519.ConstantTimeOperations](masterSecret, monero.TestNetwork, 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	testScan[curve25519.ConstantTimeOperations](t, wallet)
}
