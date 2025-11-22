package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

var testProveSpend = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("f10bf01839ea216e5d70b7c9ceaa8b8e9a432b5e98e6e48a8043ffb3fa229f0b")
var testGenerateImage = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("336e3af233b3aa5bc95d5589aba67aab727727419899823acc6a6c4479e4ea04")
var testViewIncoming = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200")
var testGenerateAddressSecret = types.MustHashFromString("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1")
var testViewBalanceSecret = types.MustHashFromString("154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5")
var testMasterSecret = types.MustHashFromString("6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e")

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
		expected := types.MustBytes32FromString[curve25519.PublicKeyBytes]("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f")
		var result curve25519.VarTimePublicKey
		MakeSpendPub(
			&result,
			testGenerateImage.Scalar(),
			testProveSpend.Scalar(),
		)
		if result.AsBytes() != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_spend_pubkey_from_spendpub", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PublicKeyBytes]("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f")

		var proveSpendPub curve25519.VarTimePublicKey
		proveSpendPub.ScalarMultPrecomputed(testProveSpend.Scalar(), crypto.GeneratorT)

		var result curve25519.VarTimePublicKey
		MakeSpendPubFromSpendPub(
			&result,
			testGenerateImage.Scalar(),
			&proveSpendPub,
		)
		if result.AsBytes() != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_index_extension_generator", func(t *testing.T) {
		expected := types.MustHashFromString("79ad2383f44b4d26413adb7ae79c5658b2a8c20b6f5046bfa9f229bfcf1744a7")
		result := MakeIndexExtensionGenerator(
			&blake2b.Digest{},
			testGenerateAddressSecret,
			address.SubaddressIndex{Account: 5, Offset: 16},
		)
		if result != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_subaddress_scalar", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("824e9710a9ee164dcf225be9ced906ceb53a0e93326b199a79340f6c0c7e050d")
		var result curve25519.Scalar
		MakeSubaddressScalar(
			&blake2b.Digest{},
			&result,
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f"),
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("a30c1b720a66557c03a9784c6dd0902c95ee56670e04907d18eaa20608a72e7e"),
			types.MustHashFromString("79ad2383f44b4d26413adb7ae79c5658b2a8c20b6f5046bfa9f229bfcf1744a7"),
			address.SubaddressIndex{Account: 5, Offset: 16},
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != expected {
			t.Fatalf("expected: %s, got: %x", expected.String(), result.Bytes())
		}
	})
}
