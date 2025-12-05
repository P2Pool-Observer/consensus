package cryptonote

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

var testGeneralFundAddr = address.FromBase58("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
var testGeneralFundViewKey = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("f359631075708155cc3d92a32b75a7d02a5dcf27756707b47a2b31b21c389501")
var testGeneralFundDonationAddr = address.FromBase58("888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H")

func TestGetSubaddress(t *testing.T) {

	sa := GetSubaddress(testGeneralFundAddr, testGeneralFundViewKey.Scalar(), address.SubaddressIndex{Offset: 70})

	if sa == nil {
		t.Fatal("GetSubaddress returned nil")
	}

	if !sa.IsSubaddress() {
		t.Fatal("IsSubaddress returned false")
	}

	if sa.Compare(testGeneralFundDonationAddr) != 0 {
		t.Logf("got  spend %s", sa.SpendPublicKey().String())
		t.Logf("got  view %s", sa.ViewPublicKey().String())
		t.Logf("need spend %s", testGeneralFundDonationAddr.SpendPublicKey().String())
		t.Logf("need view %s", testGeneralFundDonationAddr.ViewPublicKey().String())
		t.Fatalf("expected %s, got %s", string(testGeneralFundDonationAddr.ToBase58()), string(sa.ToBase58()))
	}
}

func TestGetSubaddressFakeAddress(t *testing.T) {

	sa := GetSubaddressFakeAddress(testGeneralFundDonationAddr, testGeneralFundViewKey.Scalar())

	if sa == nil {
		t.Fatal("GetSubaddressFakeAddress returned nil")
	}
}
