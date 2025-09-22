package address

import (
	"encoding/binary"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"github.com/tmthrgd/go-hex"
)

func TestViewWallet(t *testing.T) {
	vw, err := NewViewWallet(testGeneralFundAddr, &testGeneralFundViewKey, 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	if sa := vw.Get(SubaddressIndex{0, 70}); sa.Compare(testGeneralFundDonationAddr) != 0 {
		t.Fatalf("expected %s, got %s", string(testGeneralFundDonationAddr.ToBase58()), string(sa.ToBase58()))
	}

	var ecdhInfo []uint64

	// from 0b0ff5efc5e1a277f256501a4df8e86eb3387828c1cf235a93702a9c16548965

	for _, o := range []string{"46cd3b24cca1aa6c", "bbb7ce98edb2d678"} {
		buf, err := hex.DecodeString(o)
		if err != nil {
			t.Fatal(err)
		}
		ecdhInfo = append(ecdhInfo, binary.LittleEndian.Uint64(buf))
	}

	txPub := crypto.PublicKeyBytes(types.MustHashFromString("889432b1c870f2c5748b4c6f8bd2f28879cc698859674940b082b5fb5fef7e90"))
	outputs := transaction.Outputs{
		{
			Index:              0,
			Reward:             0,
			EphemeralPublicKey: crypto.PublicKeyBytes(types.MustHashFromString("892251b8fa9b95f90397f17f20178e05be9122338c1be821cb208237ce3397ca")),
			Type:               transaction.TxOutToTaggedKey,
			ViewTag:            0xc0,
		},
		{
			Index:              1,
			Reward:             0,
			EphemeralPublicKey: crypto.PublicKeyBytes(types.MustHashFromString("8219a994a9055ce3f99298fae343afea6b2d658098b33099b65b78e160cbd72e")),
			Type:               transaction.TxOutToTaggedKey,
			ViewTag:            0x82,
		},
	}

	i, pub, sharedData, ix := vw.Match(outputs, txPub)
	if i == -1 {
		t.Fatal("expected to find output")
	}
	if pub != txPub {
		t.Fatal("expected to find same public key")
	}

	if ix.Account != 0 || ix.Offset != 70 {
		t.Fatalf("unexpected account %d or offset %d", ix.Account, ix.Offset)
	}

	const expected = 3284260000
	if amount := crypto.DecryptOutputAmount(sharedData, ecdhInfo[i]); amount != expected {
		t.Fatalf("expected %d, got %d", expected, amount)
	}
}
