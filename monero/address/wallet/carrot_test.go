package wallet

import (
	"crypto/rand"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestCarrotViewWallet_Match(t *testing.T) {
	var masterSecret types.Hash
	_, _ = rand.Read(masterSecret[:])
	vw, err := NewCarrotViewWalletFromMasterSecret(masterSecret, monero.TestNetwork, 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	testScanCoinbase(t, vw, address.ZeroSubaddressIndex)
	testScanCoinbase(t, vw, testGeneralFundSubaddressIndex)

	testScanPayment(t, vw, address.ZeroSubaddressIndex)
	testScanPayment(t, vw, testGeneralFundSubaddressIndex)
}
