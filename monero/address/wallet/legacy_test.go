package wallet

import (
	"crypto/rand"
	"os"
	"path"
	"runtime"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

func init() {
	_, filename, _, _ := runtime.Caller(0)
	// The ".." may change depending on you folder structure
	dir := path.Join(path.Dir(filename), "../../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

}

var testGeneralFundAddr = address.FromBase58("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
var testGeneralFundViewKey = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("f359631075708155cc3d92a32b75a7d02a5dcf27756707b47a2b31b21c389501")
var testGeneralFundDonationAddr = address.FromBase58("888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H")
var testGeneralFundSubaddressIndex = address.SubaddressIndex{Account: 0, Offset: 70}

func TestViewWallet_GeneralFund_Match(t *testing.T) {
	vw, err := NewViewWallet[curve25519.VarTimeOperations](testGeneralFundAddr, testGeneralFundViewKey.Scalar(), 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	sa := vw.Get(testGeneralFundSubaddressIndex)
	if sa.Compare(testGeneralFundDonationAddr) != 0 {
		t.Fatalf("expected %s, got %s", string(testGeneralFundDonationAddr.ToBase58()), string(sa.ToBase58()))
	}

	commitments := make([]ringct.CommitmentEncryptedAmount, 2)

	txId := types.MustHashFromString("0b0ff5efc5e1a277f256501a4df8e86eb3387828c1cf235a93702a9c16548965")

	for i, o := range []string{"add031be3b52ddfb3dc95c1e8a190eff69633925a9a52c6d28263db7413f21b0", "e4a9a76ec76c601a809d689402303117489b63ec6e1bf8c985e71f75ac2feebe"} {
		buf, err := hex.DecodeString(o)
		if err != nil {
			t.Fatal(err)
		}
		copy(commitments[i].Commitment[:], buf)
	}

	for i, o := range []string{"46cd3b24cca1aa6c", "bbb7ce98edb2d678"} {
		buf, err := hex.DecodeString(o)
		if err != nil {
			t.Fatal(err)
		}
		copy(commitments[i].Amount[:], buf)
	}

	txPub := types.MustBytes32FromString[curve25519.PublicKeyBytes]("889432b1c870f2c5748b4c6f8bd2f28879cc698859674940b082b5fb5fef7e90")
	outputs := transaction.Outputs{
		{
			Index:              0,
			Amount:             0,
			EphemeralPublicKey: types.MustBytes32FromString[curve25519.PublicKeyBytes]("892251b8fa9b95f90397f17f20178e05be9122338c1be821cb208237ce3397ca"),
			Type:               transaction.TxOutToTaggedKey,
			ViewTag:            types.MakeFixed([monero.CarrotViewTagSize]byte{0xc0}),
		},
		{
			Index:              1,
			Amount:             0,
			EphemeralPublicKey: types.MustBytes32FromString[curve25519.PublicKeyBytes]("8219a994a9055ce3f99298fae343afea6b2d658098b33099b65b78e160cbd72e"),
			Type:               transaction.TxOutToTaggedKey,
			ViewTag:            types.MakeFixed([monero.CarrotViewTagSize]byte{0x82}),
		},
	}

	// todo: payment id
	i, scan, ix := vw.Match(outputs, commitments, []curve25519.PublicKeyBytes{txPub}, nil)
	if i == -1 {
		t.Fatal("expected to find output")
	}

	if ix.Account != 0 || ix.Offset != 70 {
		t.Fatalf("unexpected account %d or offset %d", ix.Account, ix.Offset)
	}

	const expected = 3284260000
	if scan.Amount != expected {
		t.Fatalf("expected %d, got %d", uint64(expected), scan.Amount)
	}

	var txPubPoint curve25519.VarTimePublicKey
	_, _ = txPubPoint.SetBytes(txPub[:])

	inProof := address.GetInProof(sa, txId, vw.ViewKey(), &txPubPoint, "", 2)

	pI, pOk := address.VerifyTxProof(inProof, sa, txId, &txPubPoint, "")
	if pI == -1 || !pOk {
		t.Fatal("expected to verify proof")
	}
}

func TestViewWallet_GeneralFund_KeyImages(t *testing.T) {
	vw, err := NewViewWallet[curve25519.ConstantTimeOperations](testGeneralFundAddr, testGeneralFundViewKey.Scalar(), 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("testdata/getmonero_key_images_GF_until_20250206")
	if err != nil {
		t.Fatal(err)
	}

	export, err := DecryptKeyImages[curve25519.VarTimeOperations](data, vw.ViewKey(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, ki := range export.Images {
		t.Logf("#%04d: ki = %x", i, ki.KI.Bytes())
	}

}

func TestViewWallet_Match(t *testing.T) {
	var spendKey curve25519.Scalar
	curve25519.RandomScalar(&spendKey, rand.Reader)

	wallet, err := NewSpendWalletFromSpendKey[curve25519.ConstantTimeOperations](&spendKey, monero.TestNetwork, 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	testScanCoinbase[curve25519.ConstantTimeOperations](t, wallet, address.ZeroSubaddressIndex)
	testScanCoinbase[curve25519.ConstantTimeOperations](t, wallet, testGeneralFundSubaddressIndex)

	testScanPayment[curve25519.ConstantTimeOperations](t, wallet, address.ZeroSubaddressIndex)
	testScanPayment[curve25519.ConstantTimeOperations](t, wallet, testGeneralFundSubaddressIndex)
}
