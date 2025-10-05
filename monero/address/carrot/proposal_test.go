package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"github.com/tmthrgd/go-hex"
)

func TestPaymentProposalV1_CoinbaseOutput(t *testing.T) {
	expectedEnote := &CoinbaseEnoteV1{
		OneTimeAddress:  crypto.PublicKeyBytes(types.MustHashFromString("a3d1d782671a3622bf393fe8116c8df95e9e12776e2970ab1934645f40748343")),
		Amount:          monero.TailEmissionReward,
		EncryptedAnchor: [monero.JanusAnchorSize]byte(hex.MustDecodeString("fa1d74f7a4891086a900e72776c521ed")),
		ViewTag:         [monero.CarrotViewTagSize]byte(hex.MustDecodeString("74b582")),
		EphemeralPubKey: crypto.X25519PublicKey(types.MustHashFromString("1b10ce3755cc36e2fda4031a56b589f29e2e727ab0e222be05f30f84c5c1b747")),
		BlockIndex:      123456,
	}

	addr := address.PackedAddress{
		crypto.PublicKeyBytes(types.MustHashFromString("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")),
		crypto.PublicKeyBytes(types.MustHashFromString("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")),
	}
	proposal := &PaymentProposalV1{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(&addr, false),
			PaymentId: [8]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55")),
	}

	enote, err := proposal.CoinbaseOutput(123456)
	if err != nil {
		t.Fatalf("failed to generate coinbase enote: %s", err)
	}

	if *expectedEnote != *enote {
		t.Fatalf("coinbase enote does not match expected enote: expected %+v, got %+v", *expectedEnote, *enote)
	}

}
