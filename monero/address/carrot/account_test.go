package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

var testProveSpend = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("c9651fc906015afeefdb8d3bf7be621c36e035de2a85cb22dd4b869a22086f0e")
var testGenerateImage = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("2ec40d3dd3a06b2f9a580c41e852be26950b7398d27f248efad5a81cdeead70b")
var testViewIncoming = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("12624c702b4c1a22fd710a836894ed0705955502e6498e5c6e3ad6f5920bb00f")
var testGenerateAddressSecret = types.MustHashFromString("039f0744fb138954072ee6bcbda4b5c085fd05e09b476a7b34ad20bf9ad440bc")
var testViewBalanceSecret = types.MustHashFromString("59b2ee8646923309384704613418f5982b0167eb3cd87c6c067ee10700c3af91")
var testMasterSecret = types.MustHashFromString("6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e")

var testCarrotSpendPubkey = types.MustBytes32FromString[curve25519.PublicKeyBytes]("674a9892b538aaaafa2412dabf13a2e3f843c7e323810630d05c10cc64077077")
var testCarrotViewPubkey = types.MustBytes32FromString[curve25519.PublicKeyBytes]("55960ccffdfb5e596b867658ac881f4d378e45bb76395964f2402037ec4685ff")
var testCarrotIndexExtensionGenerator = types.MustHashFromString("fa26210179cdf94ae6ca2a7c93620909cb77e4923478a204ebe93794ab30bc7a")

// testSubaddress generated from index 5, 16 from above values
// see TestDestinationV1_ConvergeMakeSubaddress
var testSubaddress = address.NewPackedAddressWithSubaddressFromBytes(
	types.MustBytes32FromString[curve25519.PublicKeyBytes]("837744f1da3cbefcf64214b88e1a4c6dbbac5d18965d8052648486a74a2b08bb"),
	types.MustBytes32FromString[curve25519.PublicKeyBytes]("d8b83883dd375b3a7536d9a9ceffa6c6505fbffbee883d825d32c25b99a9a450"),
	true,
)

func TestConvergeAccount(t *testing.T) {

	t.Run("make_carrot_provespend_key", func(t *testing.T) {
		var result curve25519.Scalar
		MakeProveSpendKey(
			&blake2b.Digest{},
			&result,
			testMasterSecret,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testProveSpend {
			t.Fatalf("expected: %s, got: %x", testProveSpend.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_viewbalance_secret", func(t *testing.T) {
		result := MakeViewBalanceSecret(
			&blake2b.Digest{},
			testMasterSecret,
		)
		if result != testViewBalanceSecret {
			t.Fatalf("expected: %s, got: %s", testViewBalanceSecret.String(), result.String())
		}
	})

	t.Run("make_carrot_generateimage_key", func(t *testing.T) {
		var result curve25519.Scalar
		MakeGenerateImageKey(
			&blake2b.Digest{},
			&result,
			testViewBalanceSecret,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testGenerateImage {
			t.Fatalf("expected: %s, got: %x", testGenerateImage.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_viewincoming_key", func(t *testing.T) {
		var result curve25519.Scalar
		MakeViewIncomingKey(
			&blake2b.Digest{},
			&result,
			testViewBalanceSecret,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testViewIncoming {
			t.Fatalf("expected: %s, got: %x", testViewIncoming.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_generateaddress_secret", func(t *testing.T) {
		result := MakeGenerateAddressSecret(
			&blake2b.Digest{},
			testViewBalanceSecret,
		)
		if result != testGenerateAddressSecret {
			t.Fatalf("expected: %s, got: %s", testGenerateAddressSecret.String(), result.String())
		}
	})

	t.Run("make_carrot_spend_pubkey", func(t *testing.T) {
		var result curve25519.VarTimePublicKey
		MakeSpendPub(
			&result,
			testGenerateImage.Scalar(),
			testProveSpend.Scalar(),
		)
		if result.AsBytes() != testCarrotSpendPubkey {
			t.Fatalf("expected: %s, got: %s", testCarrotSpendPubkey.String(), result.String())
		}
	})

	t.Run("make_carrot_view_pubkey", func(t *testing.T) {
		var result curve25519.VarTimePublicKey
		MakeAccountViewPub(
			&result,
			testViewIncoming.Scalar(),
			testCarrotSpendPubkey.PointVarTime(),
		)
		if result.AsBytes() != testCarrotViewPubkey {
			t.Fatalf("expected: %s, got: %s", testCarrotViewPubkey.String(), result.String())
		}
	})

	t.Run("make_carrot_spend_pubkey_from_spendpub", func(t *testing.T) {
		var proveSpendPub curve25519.VarTimePublicKey
		proveSpendPub.ScalarMultPrecomputed(testProveSpend.Scalar(), crypto.GeneratorT)

		var result curve25519.VarTimePublicKey
		MakeSpendPubFromSpendPub(
			&result,
			testGenerateImage.Scalar(),
			&proveSpendPub,
		)
		if result.AsBytes() != testCarrotSpendPubkey {
			t.Fatalf("expected: %s, got: %s", testCarrotSpendPubkey.String(), result.String())
		}
	})

	t.Run("make_carrot_index_extension_generator", func(t *testing.T) {
		result := MakeIndexExtensionGenerator(
			&blake2b.Digest{},
			testGenerateAddressSecret,
			address.SubaddressIndex{Account: 5, Offset: 16},
		)
		if result != testCarrotIndexExtensionGenerator {
			t.Fatalf("expected: %s, got: %s", testCarrotIndexExtensionGenerator.String(), result.String())
		}
	})

	t.Run("make_carrot_subaddress_scalar", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("70b70912ffa1c01e073ef1e0a7cd46c810f839fe57ca3d0af1f3451194d56408")
		var result curve25519.Scalar
		MakeSubaddressScalar(
			&blake2b.Digest{},
			&result,
			testCarrotSpendPubkey,
			testCarrotViewPubkey,
			testCarrotIndexExtensionGenerator,
			address.SubaddressIndex{Account: 5, Offset: 16},
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != expected {
			t.Fatalf("expected: %s, got: %x", expected.String(), result.Bytes())
		}
	})
}
