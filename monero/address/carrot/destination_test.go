package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestDestinationV1_ConvergeMakeSubaddress(t *testing.T) {
	expected := address.NewPackedAddressFromBytes(
		types.MustBytes32FromString[curve25519.PublicKeyBytes]("cb84becce21364e6fc91f6cec459ae917287bc3d87791369f8ff0fc40e4fcc08"),
		types.MustBytes32FromString[curve25519.PublicKeyBytes]("82800b2b97f50a798768d3235eabe9d4b3d5bd6d12956975b79db53f29895bdd"),
	)

	generateAddress := types.MustHashFromString("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1")

	spendPub := types.MustBytes32FromString[curve25519.PublicKeyBytes]("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f")
	viewKey := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200")
	var accountViewPub curve25519.VarTimePublicKey

	spendPubPoint := curve25519.DecodeCompressedPoint(new(curve25519.VarTimePublicKey), spendPub)
	MakeAccountViewPub(&accountViewPub, viewKey.Scalar(), spendPubPoint)

	subaddress, err := MakeDestinationSubaddress(
		&blake2b.Digest{},
		spendPubPoint,
		&accountViewPub,
		generateAddress,
		address.SubaddressIndex{Account: 5, Offset: 16},
	)
	if err != nil {
		t.Fatalf("failed to make subaddress: %v", err)
	}
	if *subaddress.Address.SpendPublicKey() != *expected.SpendPublicKey() {
		t.Fatalf("expected: %s, got: %s", expected.SpendPublicKey().String(), subaddress.Address.SpendPublicKey().String())
	}
	if *subaddress.Address.ViewPublicKey() != *expected.ViewPublicKey() {
		t.Fatalf("expected: %s, got: %s", expected.ViewPublicKey().String(), subaddress.Address.ViewPublicKey().String())
	}
}
