package carrot

import (
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

var testAnchorNorm = [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55"))
var testInputContext = hex.MustDecodeString("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")

var testEphemeralPriv = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303")

var testEphemeralPubCryptonote = types.MustBytes32FromString[curve25519.MontgomeryPoint]("8df2a40a42ecc10348a461310c1afc2c2b1be7b29fd27a3921a1aefba5efa27b")
var testEphemeralPubSubaddress = types.MustBytes32FromString[curve25519.MontgomeryPoint]("a3c3cdf84fd301cfc4675096f1c896543f2efc1001d899bbab3a0fd137f6a630")

var testSenderReceiverUnctx = types.MustBytes32FromString[curve25519.MontgomeryPoint]("1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49")
var testSecretSenderReceiver = types.MustHashFromString("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6")

const testAmount = 67000000000000

var testAmountBlindingFactorPayment = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("5a01cc9f8ca9556c429d623d848fe036c76593005c63a62df57afc4b51d3c20b")
var testAmountBlindingFactorChange = types.MustBytes32FromString[curve25519.PrivateKeyBytes]("f69587a2e01d039758b5dd61999e4d60f226eb7b8027be2ff2656ecbb584d103")
var testAmountCommitment = types.MustBytes32FromString[curve25519.PublicKeyBytes]("f5df40aeba877e8ccadd9dff363d90ec28efbfd1201573897cd70c61c026edb9")

var testOnetimeAddressCoinbase = types.MustBytes32FromString[curve25519.PublicKeyBytes]("0c4ee83d079ebd77882f894b2e0a43e3d572af9c330871f1dfbcc62f5c64e4ae")
var testOnetimeAddress = types.MustBytes32FromString[curve25519.PublicKeyBytes]("522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516")

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
		expected := [monero.CarrotViewTagSize]byte(hex.MustDecodeString("5f58e1"))
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
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("6ba7e188fb315ad2158ac6b6652408d4"))
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
		expected := [monero.EncryptedAmountSize]byte(hex.MustDecodeString("2b739fdb6d1d5e50"))
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
		expected := [monero.PaymentIdSize]byte(hex.MustDecodeString("043d7e9ed13a3484"))
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
		expected := [monero.JanusAnchorSize]byte(hex.MustDecodeString("70fe9b941fe1ef3b2345c87485f70a6e"))
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
