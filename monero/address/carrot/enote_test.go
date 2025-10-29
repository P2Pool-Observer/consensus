package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

var testViewKey = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200")

var testAddress = address.PackedAddress{
	types.MustBytes32FromString[curve25519.PublicKeyBytes]("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
	types.MustBytes32FromString[curve25519.PublicKeyBytes]("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2"),
}

var testEphemeralPriv = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("f57ff2d7c898b755137b69e8d826801945ed72e9951850de908e9d645a0bb00d")
var testEphemeralPub = types.MustBytes32FromString[curve25519.MontgomeryPoint]("d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55")

var testSecretSenderReceiver = types.MustHashFromString("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c")

var testSenderReceiverUnctx = types.MustBytes32FromString[curve25519.MontgomeryPoint]("baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451")

var testInputContext = hex.MustDecodeString("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")

func TestConverge(t *testing.T) {
	t.Parallel()

	// tests from Carrot convergence testing
	// https://github.com/seraphis-migration/monero/pull/121
	// todo: update as needed

	t.Run("make_carrot_enote_ephemeral_privkey", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("6d4645a0e398ff430f68eaa78240dd2c04051e9a50438cd9c9c3c0e12af68b0b")
		var result curve25519.Scalar
		makeEnoteEphemeralPrivateKey(
			&blake2b.Digest{},
			&result,
			hex.MustDecodeString("caee1381775487a0982557f0d2680b55"),
			testInputContext,
			*testAddress.SpendPublicKey(),
			[8]byte(hex.MustDecodeString("4321734f56621440")),
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != expected {
			t.Fatalf("expected: %s, got: %x", expected.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_enote_ephemeral_pubkey_cryptonote", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.MontgomeryPoint]("2987777565c02409dfe871cc27b2334f5ade9d4ad014012c568367b80e99c666")
		result := makeEnoteEphemeralPublicKeyCryptonote[curve25519.VarTimeOperations](
			testEphemeralPriv.Scalar(),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_enote_ephemeral_pubkey_subaddress", func(t *testing.T) {
		expected := testEphemeralPub
		result := makeEnoteEphemeralPublicKeySubaddress(
			testEphemeralPriv.Scalar(),
			testAddress.SpendPublicKey().PointVarTime(),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_uncontextualized_shared_key_receiver", func(t *testing.T) {
		expected := testSenderReceiverUnctx
		result := MakeUncontextualizedSharedKeyReceiver(
			testViewKey.Scalar(),
			&testEphemeralPub,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_uncontextualized_shared_key_sender", func(t *testing.T) {
		expected := testSenderReceiverUnctx
		result := makeUncontextualizedSharedKeySender(
			testEphemeralPriv.Scalar(),
			testAddress.ViewPublicKey().PointVarTime(),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}

		result2 := makeUncontextualizedSharedKeySenderVarTime(
			testEphemeralPriv.Scalar(),
			testAddress.ViewPublicKey().PointVarTime(),
		)
		if result2 != expected {
			t.Fatalf("expected: %x, got: %x", expected, result2)
		}
	})

	t.Run("make_carrot_sender_receiver_secret", func(t *testing.T) {
		expected := testSecretSenderReceiver
		result := makeSenderReceiverSecret(
			&blake2b.Digest{},
			testSenderReceiverUnctx,
			testEphemeralPub,
			testInputContext,
		)
		if result != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_amount_blinding_factor_payment", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("9fc3581e926a844877479d829ff9deeae17ce77feaf2c3c972923510e04f1f02")
		var result curve25519.Scalar
		makeAmountBlindingFactor(
			&blake2b.Digest{},
			&result,
			testSecretSenderReceiver,
			23000000000000,
			*testAddress.SpendPublicKey(),
			EnoteTypePayment,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != expected {
			t.Fatalf("expected: %s, got: %x", expected.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_blinding_factor_change", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("dda34eac46030e4084f5a2c808d0a82ffaa82cbf01d4a74d7ee0d4fe72c31a0f")
		var result curve25519.Scalar
		makeAmountBlindingFactor(
			&blake2b.Digest{},
			&result,
			testSecretSenderReceiver,
			23000000000000,
			*testAddress.SpendPublicKey(),
			EnoteTypeChange,
		)
		if curve25519.PrivateKeyBytes(result.Bytes()) != expected {
			t.Fatalf("expected: %s, got: %x", expected.String(), result.Bytes())
		}
	})

	t.Run("make_carrot_amount_commitment", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PublicKeyBytes]("ca5f0fc2fe7a4fe628e6f08b2c0eb44f3af3b87e1619b2ed2de296f7e425512b")
		amountBlindingFactor := types.MustBytes32FromString[curve25519.PrivateKeyBytes]("9fc3581e926a844877479d829ff9deeae17ce77feaf2c3c972923510e04f1f02")
		result := makeAmountCommitment[curve25519.VarTimeOperations](
			23000000000000,
			amountBlindingFactor.Scalar(),
		)
		if result != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_onetime_address", func(t *testing.T) {
		expected := types.MustBytes32FromString[curve25519.PublicKeyBytes]("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
		result := makeOnetimeAddress(
			&blake2b.Digest{},
			testAddress.SpendPublicKey().PointVarTime(),
			testSecretSenderReceiver,
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("ca5f0fc2fe7a4fe628e6f08b2c0eb44f3af3b87e1619b2ed2de296f7e425512b"),
		)
		if result != expected {
			t.Fatalf("expected: %s, got: %s", expected.String(), result.String())
		}
	})

	t.Run("make_carrot_view_tag", func(t *testing.T) {
		expected := [monero.CarrotViewTagSize]byte(hex.MustDecodeString("0176f6"))
		result := makeViewTag(
			&blake2b.Digest{},
			testSenderReceiverUnctx,
			testInputContext,
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92"),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_anchor_encryption_mask", func(t *testing.T) {
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("52d95a8e441f26a056f55094938cbfa8"))
		result := makeAnchorEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92"),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_amount_encryption_mask", func(t *testing.T) {
		expected := [monero.EncryptedAmountSize]byte(hex.MustDecodeString("98d25d1db65b6a3e"))
		result := makeAmountEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92"),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_payment_id_encryption_mask", func(t *testing.T) {
		expected := [monero.PaymentIdSize]byte(hex.MustDecodeString("b57a1560e82e2483"))
		result := makePaymentIdEncryptionMask(
			&blake2b.Digest{},
			testSecretSenderReceiver,
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92"),
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})

	t.Run("make_carrot_payment_id_encryption_mask", func(t *testing.T) {
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("31afa8f580feaf736cd424ecc9ae5fd2"))
		result := makeJanusAnchorSpecial(
			&blake2b.Digest{},
			testEphemeralPub,
			testInputContext,
			types.MustBytes32FromString[curve25519.PublicKeyBytes]("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92"),
			testViewKey,
		)
		if result != expected {
			t.Fatalf("expected: %x, got: %x", expected, result)
		}
	})
}
