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

var testEphemeralPubCryptonote = types.MustBytes32FromString[curve25519.MontgomeryPoint]("81f59f8d2207ce0403a552c7069d8b35945d25bb1426417d71860be2c2efbc44")

var testSecretSenderReceiver = types.MustHashFromString("300f88e1626c74c97e8b2f3d627a0444a34d515d8657c2e7dc2291e75727e268")

var testSenderReceiverUnctx = types.MustBytes32FromString[curve25519.MontgomeryPoint]("ae62faa4d5b1277fe9c4777a950969f56deee7bfba7b2c2921e301e12f46411d")

var testInputContext = hex.MustDecodeString("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")

var testRandomness = [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55"))

var testCarrotAmountBlindingFactorPayment = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("ee02780bf4b4a90a9577e694bbba25264f2604e4933590bd1efffd2a558a4d0a")
var testCarrotAmountCommitment = types.MustBytes32FromString[curve25519.PublicKeyBytes]("edd30d1b0808defb3c5a33dcc55dd05a1b197242f427f88f80b4dda63ed39958")
var testCarrotOnetimeAddress = types.MustBytes32FromString[curve25519.PublicKeyBytes]("1e3c78039277f79d373e21c629291e49d64a36dd1948c6913227da1088e66280")

const testAmount = 67000000000000

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
		result := makeEnoteEphemeralPublicKeyCryptonote[curve25519.VarTimeOperations](
			testEphemeralPriv.Scalar(),
		)
		if result != testEphemeralPubCryptonote {
			t.Fatalf("expected: %x, got: %x", testEphemeralPubCryptonote, result)
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
			testAmount,
			*testSubaddress.SpendPublicKey(),
			EnoteTypePayment,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != testCarrotAmountBlindingFactorPayment {
			t.Fatalf("expected: %s, got: %x", testCarrotAmountBlindingFactorPayment.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_blinding_factor_change", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("abac509b18e04c39a70a3e1e72b4c06b7b21c43dd95c2d2e97ceace6c44ba90c")
		var result curve25519.Scalar
		makeAmountBlindingFactor(
			&blake2b.Digest{},
			&result,
			testSecretSenderReceiver,
			testAmount,
			*testSubaddress.SpendPublicKey(),
			EnoteTypeChange,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != expected {
			t.Fatalf("expected: %s, got: %x", expected.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_commitment", func(t *testing.T) {
		result := makeAmountCommitment[curve25519.VarTimeOperations](
			testAmount,
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
		expected := [monero.CarrotViewTagSize]byte(hex.MustDecodeString("93096d"))
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
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("c6df4ecdfe1beed0cdadf0483467391e"))
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
		expected := [monero.EncryptedAmountSize]byte(hex.MustDecodeString("2a982ec96a940a5d"))
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
		expected := [monero.PaymentIdSize]byte(hex.MustDecodeString("39b004624a1170d4"))
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
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("cea1a83cbe3b2c82f36fbcb4d5af85d8"))
		result := makeJanusAnchorSpecial(
			&blake2b.Digest{},
			testEphemeralPubCryptonote,
			testInputContext,
			testCarrotOnetimeAddress,
			testViewIncoming,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})
}
