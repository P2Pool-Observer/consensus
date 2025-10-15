package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestDestinationV1_ConvergeMakeSubaddress(t *testing.T) {
	expected := address.NewPackedAddressFromBytes(
		crypto.PublicKeyBytes(types.MustHashFromString("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")),
		crypto.PublicKeyBytes(types.MustHashFromString("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")),
	)

	generateAddress := types.MustHashFromString("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1")

	spendPub := crypto.PublicKeyBytes(types.MustHashFromString("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f"))
	viewKey := crypto.PrivateKeyBytes(types.MustHashFromString("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200"))
	var accountViewPub crypto.PublicKeyPoint
	MakeAccountViewPub(&accountViewPub, viewKey.AsScalar(), spendPub.AsPoint())

	subaddress, err := MakeDestinationSubaddress(
		&blake2b.Digest{},
		spendPub.AsPoint(),
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
