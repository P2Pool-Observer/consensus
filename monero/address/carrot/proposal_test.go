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
		OneTimeAddress:  types.MustBytes32FromString[curve25519.PublicKeyBytes]("67d9b0756a3ef52a1d8c56dbc2259fbb14970c4e55c952c1f836060b943fa721"),
		Amount:          testAmount,
		EncryptedAnchor: types.MakeFixed([monero.JanusAnchorSize]byte(hex.MustDecodeString("93cf5339e417f46e1dc6ec5e94eb4d1e"))),
		ViewTag:         types.MakeFixed([monero.CarrotViewTagSize]byte(hex.MustDecodeString("3f379d"))),
		EphemeralPubKey: types.MustBytes32FromString[curve25519.MontgomeryPoint]("7c722a4d48061aac74ef1677828049a77819a933f892d0cd12ab2ad60c98284f"),
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
	err := proposal.CoinbaseOutput(&enote, expectedEnote.BlockIndex)
	if err != nil {
		t.Fatalf("failed to generate coinbase enote: %s", err)
	}

	if expectedEnote != enote {
		t.Fatalf("coinbase enote does not match expected enote: expected %+v, got %+v", expectedEnote, enote)
	}
}
