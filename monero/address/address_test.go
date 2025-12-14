package address

import (
	"bytes"
	"crypto/rand"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	fasthex "github.com/tmthrgd/go-hex"
)

var privateKey = new(curve25519.Scalar)

var testAddress = FromBase58("42HEEF3NM9cHkJoPpDhNyJHuZ6DFhdtymCohF9CwP5KPM1Mp3eH2RVXCPRrxe4iWRogT7299R8PP7drGvThE8bHmRDq1qWp")
var testAddress2 = FromBase58("4AQ3YkqG2XdWsPHEgrDGdyQLq1qMMGFqWTFJfrVQW99qPmCzZKvJqzxgf5342KC17o9bchfJcUzLhVW9QgNKTYUBLg876Gt")
var testAddress3 = FromBase58("47Eqp7fsvVnPPSU4rsXrKJhyAme6LhDRZDzFky9xWsWUS9pd6FPjJCMDCNX1NnNiDzTwfbAgGMk2N6A1aucNcrkhLffta1p")

var ephemeralPubKey, _ = fasthex.DecodeString("20efc1310db960b0e8d22c8b85b3414fcaa1ed9aab40cf757321dd6099a62d5e")

func init() {
	h, _ := fasthex.DecodeString("74b98b1e7ce5fc50d1634f8634622395ec2a19a4698a016fedd8139df374ac00")
	if _, err := privateKey.SetCanonicalBytes(h); err != nil {
		utils.Panic(err)
	}
}

func randomAddress() (addr *Address, spendKey, viewKey *curve25519.Scalar) {
	// legacy derivation
	spendKey = curve25519.RandomScalar(new(curve25519.Scalar), rand.Reader)
	viewKey = crypto.ScalarDeriveLegacy(new(curve25519.Scalar), spendKey.Bytes())

	return FromRawAddress(monero.TestNetwork, new(curve25519.VarTimePublicKey).ScalarBaseMult(spendKey).AsBytes(), new(curve25519.VarTimePublicKey).ScalarBaseMult(viewKey).AsBytes()), spendKey, viewKey
}

func TestAddress(t *testing.T) {
	spendPub, _ := new(curve25519.VarTimePublicKey).SetBytes(testAddress.SpendPublicKey()[:])
	viewPub, _ := new(curve25519.VarTimePublicKey).SetBytes(testAddress.ViewPublicKey()[:])

	derivation := GetDerivation(new(curve25519.VarTimePublicKey), viewPub, privateKey)

	sharedData := crypto.GetDerivationSharedDataForOutputIndex(new(curve25519.Scalar), derivation.AsBytes(), 37)
	ephemeralPublicKey := GetPublicKeyForSharedData(new(curve25519.VarTimePublicKey), spendPub, sharedData)

	if bytes.Compare(ephemeralPublicKey.Bytes(), ephemeralPubKey) != 0 {
		t.Fatalf("ephemeral key mismatch, expected %s, got %s", fasthex.EncodeToString(ephemeralPubKey), ephemeralPublicKey.String())
	}
}

func TestSort(t *testing.T) {
	if testAddress2.Compare(testAddress3) != -1 {
		t.Fatalf("expected address2 < address3, got %d", testAddress2.Compare(testAddress3))
	}
}

func BenchmarkPackedAddress_ComparePacked(b *testing.B) {
	a1, a2 := testAddress.ToPackedAddress(), testAddress2.ToPackedAddress()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if a1.ComparePacked(&a2) == 0 {
				panic("cannot be equal")
			}
		}
	})
	b.ReportAllocs()
}
