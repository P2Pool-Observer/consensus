package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

var testEphemeralPriv = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("7c2fbbe9d38ecc35fdeab8be7ed9659c05407a2c96d6fe251229cb8274305b07")
var testEphemeralPub = types.MustBytes32FromString[curve25519.MontgomeryPoint]("68b04386b14657aa221ac63b6b008d123e8dbd84814abcdb660997cbfa837c65")

var testSecretSenderReceiver = types.MustHashFromString("300f88e1626c74c97e8b2f3d627a0444a34d515d8657c2e7dc2291e75727e268")

var testSenderReceiverUnctx = types.MustBytes32FromString[curve25519.MontgomeryPoint]("ae62faa4d5b1277fe9c4777a950969f56deee7bfba7b2c2921e301e12f46411d")

var testInputContext = hex.MustDecodeString("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")

var testRandomness = [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55"))

var testCarrotAmountBlindingFactorPayment = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("bf7afa747e1eb42b295c2b5abdf73543c24b38735c19d0708b7b40b2c8d89304")
var testCarrotAmountCommitment = types.MustBytes32FromString[curve25519.PublicKeyBytes]("21e6c24f32253149c06ba8e712e2d388f57923977e24fde872b2daadca4fb594")
var testCarrotOnetimeAddress = types.MustBytes32FromString[curve25519.PublicKeyBytes]("89348d1b79dcee0bdcd07c0234e288c565c22c63c93dea1be254fec020b3aad3")

func TestConverge(t *testing.T) {
	t.Parallel()

	// tests from Carrot convergence testing
	// https://github.com/seraphis-migration/monero/pull/121
	// todo: update as needed

	t.Run("make_carrot_enote_ephemeral_privkey", func(t *testing.T) {
		var result curve25519.Scalar
		makeEnoteEphemeralPrivateKey(
			&blake2b.Digest{},
			&result,
			testRandomness[:],
			testInputContext,
			*testSubaddress.SpendPublicKey(),
			[8]byte(hex.MustDecodeString("4321734f56621440")),
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testEphemeralPriv {
			t.Fatalf("expected: %s, got: %x", testEphemeralPriv.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_enote_ephemeral_pubkey_cryptonote", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.MontgomeryPoint]("81f59f8d2207ce0403a552c7069d8b35945d25bb1426417d71860be2c2efbc44")
		result := makeEnoteEphemeralPublicKeyCryptonote[curve25519.VarTimeOperations](
			testEphemeralPriv.Scalar(),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_enote_ephemeral_pubkey_subaddress", func(t *testing.T) {
		result := makeEnoteEphemeralPublicKeySubaddress(
			testEphemeralPriv.Scalar(),
			testSubaddress.SpendPublicKey().PointVarTime(),
		)
		if result != testEphemeralPub {
			t.Fatalf("expected: %x, got: %x", testEphemeralPub, result)
		}
	})

	t.Run("make_carrot_uncontextualized_shared_key_receiver", func(t *testing.T) {
		result := MakeUncontextualizedSharedKeyReceiver(
			testViewIncoming.Scalar(),
			&testEphemeralPub,
		)
		if result != testSenderReceiverUnctx {
			t.Fatalf("expected: %x, got: %x", testSenderReceiverUnctx, result)
		}
	})

	t.Run("make_carrot_uncontextualized_shared_key_sender", func(t *testing.T) {
		result := makeUncontextualizedSharedKeySender(
			testEphemeralPriv.Scalar(),
			testSubaddress.ViewPublicKey().PointVarTime(),
		)
		if result != testSenderReceiverUnctx {
			t.Fatalf("expected: %x, got: %x", testSenderReceiverUnctx, result)
		}

		result2 := makeUncontextualizedSharedKeySenderVarTime(
			testEphemeralPriv.Scalar(),
			testSubaddress.ViewPublicKey().PointVarTime(),
		)
		if result2 != testSenderReceiverUnctx {
			t.Fatalf("expected: %x, got: %x", testSenderReceiverUnctx, result2)
		}
	})

	t.Run("make_carrot_sender_receiver_secret", func(t *testing.T) {
		result := makeSenderReceiverSecret(
			&blake2b.Digest{},
			testSenderReceiverUnctx,
			testEphemeralPub,
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
			23000000000000,
			*testSubaddress.SpendPublicKey(),
			EnoteTypePayment,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testCarrotAmountBlindingFactorPayment {
			t.Fatalf("expected: %s, got: %x", testCarrotAmountBlindingFactorPayment.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_blinding_factor_change", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("f1fc76828404805b6342e7714831ceb2abc2b47b5b9bc289836e6cd5ff6c440a")
		var result curve25519.Scalar
		makeAmountBlindingFactor(
			&blake2b.Digest{},
			&result,
			testSecretSenderReceiver,
			23000000000000,
			*testSubaddress.SpendPublicKey(),
			EnoteTypeChange,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != expected {
			t.Fatalf("expected: %s, got: %x", expected.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_commitment", func(t *testing.T) {
		result := makeAmountCommitment[curve25519.VarTimeOperations](
			23000000000000,
			testCarrotAmountBlindingFactorPayment.Scalar(),
		)
		if result != testCarrotAmountCommitment {
			t.Fatalf("expected: %s, got: %s", testCarrotAmountCommitment.String(), result.String())
		}
	})

	t.Run("make_carrot_onetime_address", func(t *testing.T) {
		result := makeOnetimeAddress(
			&blake2b.Digest{},
			testSubaddress.SpendPublicKey().PointVarTime(),
			testSecretSenderReceiver,
			testCarrotAmountCommitment,
		)
		if result != testCarrotOnetimeAddress {
			t.Fatalf("expected: %s, got: %s", testCarrotOnetimeAddress.String(), result.String())
		}
	})

	t.Run("make_carrot_view_tag", func(t *testing.T) {
		expected := [monero.CarrotViewTagSize]byte(hex.MustDecodeString("4eebd8"))
		result := makeViewTag(
			&blake2b.Digest{},
			testSenderReceiverUnctx,
			testInputContext,
			testCarrotOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_anchor_encryption_mask", func(t *testing.T) {
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("bf636790d8913a4d8ef7196b40566c72"))
		result := makeAnchorEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testCarrotOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_amount_encryption_mask", func(t *testing.T) {
		expected := [monero.EncryptedAmountSize]byte(hex.MustDecodeString("e8073d6c384e1138"))
		result := makeAmountEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testCarrotOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_payment_id_encryption_mask", func(t *testing.T) {
		expected := [monero.PaymentIdSize]byte(hex.MustDecodeString("0a9b8609aa81d74d"))
		result := makePaymentIdEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			testCarrotOnetimeAddress,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_janus_anchor_special", func(t *testing.T) {
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("338ac6579a3720ff202771e5df8ce9e6"))
		result := makeJanusAnchorSpecial(
			&blake2b.Digest{},
			testEphemeralPub,
			testInputContext,
			testCarrotOnetimeAddress,
			testViewIncoming,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})
}
