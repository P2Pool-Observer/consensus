package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestConvergeAccount(t *testing.T) {

	t.Run("make_carrot_provespend_key", func(t *testing.T) {
		expected := crypto.PrivateKeyBytes(types.MustHashFromString("f10bf01839ea216e5d70b7c9ceaa8b8e9a432b5e98e6e48a8043ffb3fa229f0b"))
		var result crypto.PrivateKeyScalar
		makeProveSpendKey(
			&blake2b.Digest{},
			&result,
			types.MustHashFromString("6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e"),
		)
		if result.AsBytes() != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_viewbalance_secret", func(t *testing.T) {
		expected := types.MustHashFromString("154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5")
		result := makeViewBalanceSecret(
			&blake2b.Digest{},
			types.MustHashFromString("6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e"),
		)
		if result != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_generateimage_key", func(t *testing.T) {
		expected := crypto.PrivateKeyBytes(types.MustHashFromString("336e3af233b3aa5bc95d5589aba67aab727727419899823acc6a6c4479e4ea04"))
		var result crypto.PrivateKeyScalar
		makeGenerateImageKey(
			&blake2b.Digest{},
			&result,
			types.MustHashFromString("154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"),
		)
		if result.AsBytes() != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_viewincoming_key", func(t *testing.T) {
		expected := crypto.PrivateKeyBytes(types.MustHashFromString("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200"))
		var result crypto.PrivateKeyScalar
		makeViewIncomingKey(
			&blake2b.Digest{},
			&result,
			types.MustHashFromString("154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"),
		)
		if result.AsBytes() != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_generateaddress_secret", func(t *testing.T) {
		expected := types.MustHashFromString("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1")
		result := makeGenerateAddressSecret(
			&blake2b.Digest{},
			types.MustHashFromString("154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"),
		)
		if result != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_spend_pubkey", func(t *testing.T) {
		expected := crypto.PublicKeyBytes(types.MustHashFromString("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f"))
		generateImage := crypto.PrivateKeyBytes(types.MustHashFromString("336e3af233b3aa5bc95d5589aba67aab727727419899823acc6a6c4479e4ea04"))
		proveSpend := crypto.PrivateKeyBytes(types.MustHashFromString("f10bf01839ea216e5d70b7c9ceaa8b8e9a432b5e98e6e48a8043ffb3fa229f0b"))
		var result crypto.PublicKeyPoint
		makeSpendPub(
			&result,
			generateImage.AsScalar(),
			proveSpend.AsScalar(),
		)
		if result.AsBytes() != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_index_extension_generator", func(t *testing.T) {
		expected := types.MustHashFromString("79ad2383f44b4d26413adb7ae79c5658b2a8c20b6f5046bfa9f229bfcf1744a7")
		generateAddressSecret := types.MustHashFromString("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1")
		result := makeIndexExtensionGenerator(
			&blake2b.Digest{},
			generateAddressSecret,
			address.SubaddressIndex{Account: 5, Offset: 16},
		)
		if result != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_subaddress_scalar", func(t *testing.T) {
		expected := crypto.PrivateKeyBytes(types.MustHashFromString("25d97acc4f6b58478ee97ee9b308be756401130c1e9f3a48a5370c1a2ce0e50e"))
		var result crypto.PrivateKeyScalar
		makeSubaddressScalar(
			&blake2b.Digest{},
			&result,
			crypto.PublicKeyBytes(types.MustHashFromString("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f")),
			types.MustHashFromString("79ad2383f44b4d26413adb7ae79c5658b2a8c20b6f5046bfa9f229bfcf1744a7"),
			address.SubaddressIndex{Account: 5, Offset: 16},
		)
		if result.AsBytes() != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})
}
