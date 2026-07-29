package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

var testMasterSecret = types.MustHashFromString("6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e")

var testProveSpend = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("c9651fc906015afeefdb8d3bf7be621c36e035de2a85cb22dd4b869a22086f0e")
var testPartialSpendPub = types.MustBytes32FromString[curve25519.PublicKeyBytes]("0ea83cfaa5a4b8e3fcfd1073e84459b8ecbcfa4affe6a6bf5688c113b9e9ecc3")
var testViewBalanceSecret = types.MustHashFromString("59b2ee8646923309384704613418f5982b0167eb3cd87c6c067ee10700c3af91")
var testGenerateImagePreimageSecret = types.MustHashFromString("0f3bf96a0642ab4cd10e8c64fba1cc535379ec18dbc7d304d50eb753197e266f")
var testGenerateImage = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("b5d11670cbbbf7a70aa3a6eb88723d49f645162eb3603f70854a80a8dbceb404")
var testViewIncoming = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("12624c702b4c1a22fd710a836894ed0705955502e6498e5c6e3ad6f5920bb00f")
var testGenerateAddressSecret = types.MustHashFromString("039f0744fb138954072ee6bcbda4b5c085fd05e09b476a7b34ad20bf9ad440bc")

var testAccountSpendPubkey = types.MustBytes32FromString[curve25519.PublicKeyBytes]("905f67e69c39948e03dacbcfaeb2e766bfb407cdae53f1b11a813df99d9444e5")
var testAccountViewPubkey = types.MustBytes32FromString[curve25519.PublicKeyBytes]("34e4a36c249e3e0d22a4ee4d6a4da5ee89b12dc42223a12195af8dd727eb35fc")

var testSubaddressIndex = address.SubaddressIndex{Account: 5, Offset: 16}

var testAddressIndexPreimage1 = types.MustHashFromString("9c21bf89635102f5379f97b5d08074e6ed36084544262f92a93d7644945475f1")
var testAddressIndexPreimage2 = types.MustHashFromString("97d954f490a552e9faa5db4866441c0973d0f42aec56c8c2d553f6b43b4e9580")

var testSubaddressScalar = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("fe701755513860e77ae77bdb4f3161714635e0d48cea3f4f330895e910670103")

// testSubaddress generated from index 5, 16 from above values
// see TestDestinationV1_ConvergeMakeSubaddress
var testSubaddress = address.NewPackedAddressWithSubaddressFromBytes(
	types.MustBytes32FromString[curve25519.PublicKeyBytes]("97d227d0ff67e521b805d05d3a51390fd889181e334bf68156cb1e2d5aee6dd4"),
	types.MustBytes32FromString[curve25519.PublicKeyBytes]("99a684cd429d88815cb1f90b794522b32812388a9f35120cfc08c7435f7bd51f"),
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

	t.Run("make_carrot_partial_spend_pubkey", func(t *testing.T) {
		var result curve25519.VarTimePublicKey
		MakePartialSpendPub(
			&result,
			testProveSpend.Scalar(),
		)
		if result.AsBytes() != testPartialSpendPub {
			t.Fatalf("expected: %s, got: %x", testPartialSpendPub.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_generateimage_preimage_secret", func(t *testing.T) {
		result := MakeGenerateImagePreimageSecret(
			&blake2b.Digest{},
			testViewBalanceSecret,
		)
		if result != testGenerateImagePreimageSecret {
			t.Fatalf("expected: %s, got: %x", testGenerateImagePreimageSecret.String(), result.Slice())
		}
	})

	t.Run("make_carrot_generateimage_key", func(t *testing.T) {
		var result curve25519.Scalar
		MakeGenerateImageKey(
			&blake2b.Digest{},
			&result,
			testPartialSpendPub,
			testGenerateImagePreimageSecret,
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
		if result.AsBytes() != testAccountSpendPubkey {
			t.Fatalf("expected: %s, got: %s", testAccountSpendPubkey.String(), result.String())
		}
	})

	t.Run("make_carrot_view_pubkey", func(t *testing.T) {
		var result curve25519.VarTimePublicKey
		MakeAccountViewPub(
			&result,
			testViewIncoming.Scalar(),
			testAccountSpendPubkey.PointVarTime(),
		)
		if result.AsBytes() != testAccountViewPubkey {
			t.Fatalf("expected: %s, got: %s", testAccountViewPubkey.String(), result.String())
		}
	})

	t.Run("make_carrot_spend_pubkey_from_spendpub", func(t *testing.T) {
		var proveSpendPub curve25519.VarTimePublicKey
		proveSpendPub.ScalarMultPrecomputed(testProveSpend.Scalar(), crypto.GeneratorT)

		var result curve25519.VarTimePublicKey
		MakeSpendPubFromPartialSpendPub(
			&result,
			testGenerateImage.Scalar(),
			&proveSpendPub,
		)
		if result.AsBytes() != testAccountSpendPubkey {
			t.Fatalf("expected: %s, got: %s", testAccountSpendPubkey.String(), result.String())
		}
	})

	t.Run("make_carrot_address_index_preimage_1", func(t *testing.T) {
		result := MakeAddressIndexPreimage1(
			&blake2b.Digest{},
			testGenerateAddressSecret,
			testSubaddressIndex,
		)
		if result != testAddressIndexPreimage1 {
			t.Fatalf("expected: %s, got: %s", testAddressIndexPreimage1.String(), result.String())
		}
	})

	t.Run("make_carrot_address_index_preimage_2", func(t *testing.T) {
		result := MakeAddressIndexPreimage2(
			&blake2b.Digest{},
			testAddressIndexPreimage1,
			testAccountSpendPubkey,
			testAccountViewPubkey,
			testSubaddressIndex,
		)
		if result != testAddressIndexPreimage2 {
			t.Fatalf("expected: %s, got: %s", testAddressIndexPreimage2.String(), result.String())
		}
	})

	t.Run("make_carrot_subaddress_scalar", func(t *testing.T) {
		var result curve25519.Scalar
		MakeSubaddressScalar(
			&blake2b.Digest{},
			&result,
			testAddressIndexPreimage2,
			testAccountSpendPubkey,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testSubaddressScalar {
			t.Fatalf("expected: %s, got: %x", testSubaddressScalar.String(), result.Bytes())
		}
	})
}
