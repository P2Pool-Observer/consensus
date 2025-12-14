package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/go-hex"
)

func TestPaymentProposalV1_CoinbaseOutput(t *testing.T) {
	expectedEnote := CoinbaseEnoteV1{
		OneTimeAddress:  types.MustBytes32FromString[curve25519.PublicKeyBytes]("8519e0b836e249a2870b089402ee2bf8549cb91d237dee7768a3bfe1864151f2"),
		Amount:          testAmount,
		EncryptedAnchor: types.MakeFixed([monero.JanusAnchorSize]byte(hex.MustDecodeString("a0bab247eab215b31cb61d143c72bbe1"))),
		ViewTag:         types.MakeFixed([monero.CarrotViewTagSize]byte(hex.MustDecodeString("ecd398"))),
		EphemeralPubKey: types.MustBytes32FromString[curve25519.MontgomeryPoint]("f120a52046feb1e4fac770e97eb15568f8a86b67c8478e8816086dccdb6dcc2e"),
		BlockIndex:      123456,
	}

	proposal := &PaymentProposalV1[curve25519.VarTimeOperations]{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(testSubaddress.PackedAddress(), false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     testAmount,
		Randomness: testAnchorNorm,
	}

	var enote CoinbaseEnoteV1
	err := proposal.CoinbaseOutput(&enote, 123456)
	if err != nil {
		t.Fatalf("failed to generate coinbase enote: %s", err)
	}

	if expectedEnote != enote {
		t.Fatalf("coinbase enote does not match expected enote: expected %+v, got %+v", expectedEnote, enote)
	}
}
