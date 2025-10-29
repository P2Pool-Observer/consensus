package wallet

import (
	"crypto/rand"
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestCarrotViewWallet_Match(t *testing.T) {
	var masterSecret types.Hash
	_, _ = rand.Read(masterSecret[:])

	var proveSpend curve25519.Scalar
	carrot.MakeProveSpendKey(&blake2b.Digest{}, &proveSpend, masterSecret)

	vw, err := NewCarrotViewWalletFromMasterSecret[curve25519.ConstantTimeOperations](masterSecret, monero.TestNetwork, 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	testScanCoinbase[curve25519.ConstantTimeOperations](t, vw, address.ZeroSubaddressIndex, &proveSpend)
	testScanCoinbase[curve25519.ConstantTimeOperations](t, vw, testGeneralFundSubaddressIndex, &proveSpend)

	testScanPayment[curve25519.ConstantTimeOperations](t, vw, address.ZeroSubaddressIndex, &proveSpend)
	testScanPayment[curve25519.ConstantTimeOperations](t, vw, testGeneralFundSubaddressIndex, &proveSpend)
}
