package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/go-hex"
)

var testAnchorNorm = [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55"))
var testInputContext = hex.MustDecodeString("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")

var testEphemeralPriv = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("6bd72042c79d9532a3b90b3689ee53c22725a11169ac2d251337bc4a69b2340d")

var testEphemeralPubCryptonote = types.MustBytes32FromString[curve25519.MontgomeryPoint]("65b42ef1ed3bd2ab3e6e86d17a52d832bcb6c820a8987306bedd9f6453693869")
var testEphemeralPubSubaddress = types.MustBytes32FromString[curve25519.MontgomeryPoint]("d8e787047bb21d7dd348524741c78f311f549554b6dffd71c86ecc4a98a15720")

var testSenderReceiverUnctx = types.MustBytes32FromString[curve25519.MontgomeryPoint]("513ee79c0c8d76fdd95665a36d607b618e2f76a4806cfdba340fafe64b7f805f")
var testSecretSenderReceiver = types.MustHashFromString("6d4288869ce44ed5c38d4016b33083a1a0200daa2d8afc16625702d2108b62ae")

const testAmount = 67000000000000

var testAmountBlindingFactorPayment = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("2943f1f7cdabfcfef4803fe6a36df414065e912089ebcee5dbdad32a9685060a")
var testAmountBlindingFactorChange = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("b9787d10298d13e34cf21513bce84dd1b13ae8aad6ab79794ac06a4c936e2b09")
var testAmountCommitment = types.MustBytes32FromString[curve25519.PublicKeyBytes]("95f818f40a41665950d90db8f790cd8a135403624bac284d1059aeb29652fafe")

var testOnetimeAddressCoinbase = types.MustBytes32FromString[curve25519.PublicKeyBytes]("eb6d42a2cabe4e71a0d61172ed8b528b62c0ab398cde9373dab35cc774ba7c05")
var testOnetimeAddress = types.MustBytes32FromString[curve25519.PublicKeyBytes]("5e8f18d1dd3aba72d6ea2c7cfb217573ff4baa878300bbf97b4e32c5c566050d")

func TestConverge(t *testing.T) {
	t.Parallel()

	// tests from Carrot convergence testing
	// https://github.com/seraphis-migration/monero/pull/121
	// https://github.com/seraphis-migration/monero/pull/245
	// https://github.com/seraphis-migration/monero/pull/250

	t.Run("make_carrot_enote_ephemeral_privkey", func(t *testing.T) {
		var result curve25519.Scalar
		makeEnoteEphemeralPrivateKey(
			&blake2b.Digest{},
			&result,
			testAnchorNorm[:],
			testInputContext,
			*testSubaddress.SpendPublicKey(),
			[8]byte(hex.MustDecodeString("4321734f56621440")),
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testEphemeralPriv {
			t.Fatalf("expected: %s, got: %x", testEphemeralPriv.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_enote_ephemeral_pubkey_cryptonote", func(t *testing.T) {
		result := MakeEnoteEphemeralPublicKeyCryptonote[curve25519.VarTimeOperations](
			testEphemeralPriv.Scalar(),
		)
		if result != testEphemeralPubCryptonote {
			t.Fatalf("expected: %x, got: %x", testEphemeralPubCryptonote, result)
		}
	})

	t.Run("make_carrot_enote_ephemeral_pubkey_subaddress", func(t *testing.T) {
		result := MakeEnoteEphemeralPublicKeySubaddress(
			testEphemeralPriv.Scalar(),
			testSubaddress.SpendPublicKey().PointVarTime(),
		)
		if result != testEphemeralPubSubaddress {
			t.Fatalf("expected: %x, got: %x", testEphemeralPubSubaddress, result)
		}
	})

	t.Run("make_carrot_uncontextualized_shared_key_receiver", func(t *testing.T) {
		result := MakeUncontextualizedSharedKeyReceiver(
			testViewIncoming.Scalar(),
			&testEphemeralPubSubaddress,
		)
		if result != testSenderReceiverUnctx {
			t.Fatalf("expected: %x, got: %x", testSenderReceiverUnctx, result)
		}
	})

	t.Run("make_carrot_uncontextualized_shared_key_sender", func(t *testing.T) {
		result := MakeUncontextualizedSharedKeySender(
			testEphemeralPriv.Scalar(),
			testSubaddress.ViewPublicKey().PointVarTime(),
		)
		if result != testSenderReceiverUnctx {
			t.Fatalf("expected: %x, got: %x", testSenderReceiverUnctx, result)
		}

		result2 := MakeUncontextualizedSharedKeySenderVarTime(
			testEphemeralPriv.Scalar(),
			testSubaddress.ViewPublicKey().PointVarTime(),
		)
		if result2 != testSenderReceiverUnctx {
			t.Fatalf("expected: %x, got: %x", testSenderReceiverUnctx, result2)
		}
	})

	t.Run("make_carrot_sender_receiver_secret", func(t *testing.T) {
		result := MakeSenderReceiverSecret(
			&blake2b.Digest{},
			testSenderReceiverUnctx,
			testEphemeralPubSubaddress,
			testInputContext,
		)
		if result != testSecretSenderReceiver {
			t.Fatalf("expected: %s, got: %s", testSecretSenderReceiver.String(), result.String())
		}
	})

	t.Run("make_carrot_amount_blinding_factor_payment", func(t *testing.T) {
		var result curve25519.Scalar
		makeAmountBlindingFactor(
			&blake2b.Digest{},
			&result,
			testSecretSenderReceiver,
			testAmount,
			*testSubaddress.SpendPublicKey(),
			EnoteTypePayment,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testAmountBlindingFactorPayment {
			t.Fatalf("expected: %s, got: %x", testAmountBlindingFactorPayment.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_blinding_factor_change", func(t *testing.T) {
		var result curve25519.Scalar
		makeAmountBlindingFactor(
			&blake2b.Digest{},
			&result,
			testSecretSenderReceiver,
			testAmount,
			*testSubaddress.SpendPublicKey(),
			EnoteTypeChange,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testAmountBlindingFactorChange {
			t.Fatalf("expected: %s, got: %x", testAmountBlindingFactorChange.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_commitment", func(t *testing.T) {
		result := makeAmountCommitment[curve25519.VarTimeOperations](
			testAmount,
			testAmountBlindingFactorPayment.Scalar(),
		)
		if result != testAmountCommitment {
			t.Fatalf("expected: %s, got: %s", testAmountCommitment.String(), result.String())
		}
	})

	t.Run("make_carrot_onetime_address_coinbase", func(t *testing.T) {
		result := makeOneTimeAddressCoinbase(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testAmount,
			testSubaddress.SpendPublicKey().PointVarTime(),
		)
		if result != testOnetimeAddressCoinbase {
			t.Fatalf("expected: %s, got: %s", testOnetimeAddressCoinbase.String(), result.String())
		}
	})

	t.Run("make_carrot_onetime_address", func(t *testing.T) {
		result := makeOneTimeAddress(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testSubaddress.SpendPublicKey().PointVarTime(),
			testAmountCommitment,
		)
		if result != testOnetimeAddress {
			t.Fatalf("expected: %s, got: %s", testOnetimeAddress.String(), result.String())
		}
	})

	t.Run("make_carrot_view_tag", func(t *testing.T) {
		expected := [monero.CarrotViewTagSize]byte(hex.MustDecodeString("98ad1e"))
		result := makeViewTag(
			&blake2b.Digest{},
			testSenderReceiverUnctx,
			testInputContext,
			testOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_anchor_encryption_mask", func(t *testing.T) {
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("8d769d8417759007792f824e83115408"))
		result := makeAnchorEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_amount_encryption_mask", func(t *testing.T) {
		expected := [monero.EncryptedAmountSize]byte(hex.MustDecodeString("ee875c495435d1c3"))
		result := makeAmountEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_payment_id_encryption_mask", func(t *testing.T) {
		expected := [monero.PaymentIdSize]byte(hex.MustDecodeString("736350182e1e0840"))
		result := makePaymentIdEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_janus_anchor_special", func(t *testing.T) {
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("dea14ab8268ba491238f1c554ab60d83"))
		result := makeJanusAnchorSpecial(
			&blake2b.Digest{},
			testEphemeralPubCryptonote,
			testInputContext,
			testOnetimeAddress,
			testViewIncoming,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})
}
