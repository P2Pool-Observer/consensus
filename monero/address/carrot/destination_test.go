package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

func TestDestinationV1_ConvergeMakeSubaddress(t *testing.T) {
	var accountViewPub curve25519.VarTimePublicKey

	spendPubPoint := testCarrotSpendPubkey.PointVarTime()
	MakeAccountViewPub(&accountViewPub, testViewIncoming.Scalar(), spendPubPoint)

	sa, err := MakeDestinationSubaddress(
		&blake2b.Digest{},
		spendPubPoint,
		&accountViewPub,
		testGenerateAddressSecret,
		address.SubaddressIndex{Account: 5, Offset: 16},
	)
	if err != nil {
		t.Fatalf("failed to make subaddress: %v", err)
	}

	if sa.Address != testSubaddress {
		t.Fatalf("expected: [%s, %s], got: [%s, %s]", testSubaddress.SpendPublicKey().String(), testSubaddress.ViewPublicKey().String(), sa.Address.SpendPublicKey().String(), sa.Address.ViewPublicKey().String())
	}
}
