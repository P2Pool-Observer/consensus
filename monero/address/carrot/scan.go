package carrot

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"slices"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type ScanV1 struct {
	Type                 EnoteType
	Amount               uint64
	AmountBlindingFactor curve25519.PrivateKeyBytes

	ExtensionG curve25519.Scalar
	ExtensionT curve25519.Scalar
	SpendPub   curve25519.PublicKeyBytes

	Randomness [monero.JanusAnchorSize]byte

	PaymentId [monero.PaymentIdSize]byte
}

var ErrInvalidOneTimeAddress = errors.New("invalid one time address")
var ErrMismatchedViewTag = errors.New("mismatched view tag")
var ErrMismatchedMainAddress = errors.New("mismatched main address")
var ErrJanusProtectionFailed = errors.New("janus protection check failed")
var ErrMismatchedAmountCommitment = errors.New("mismatched amount commitment")

// TryScanEnoteChecked try_scan_carrot_coinbase_enote_checked
func (enote *CoinbaseEnoteV1) TryScanEnoteChecked(scan *ScanV1, inputContext []byte, senderReceiverUnctx curve25519.MontgomeryPoint, mainAddressSpendPubs ...curve25519.PublicKeyBytes) error {
	var hasher blake2b.Digest

	// if vt' != vt, then FAIL
	nominalViewTag := makeViewTag(&hasher, senderReceiverUnctx, inputContext, enote.OneTimeAddress)
	if nominalViewTag != enote.ViewTag.Value() {
		// no match
		return ErrMismatchedViewTag
	}

	// s^ctx_sr = H_32(s_sr, D_e, input_context)
	senderReceiverSecret := MakeSenderReceiverSecret(&hasher, senderReceiverUnctx, enote.EphemeralPubKey, inputContext)

	var oneTimeAddress curve25519.VarTimePublicKey
	if _, err := oneTimeAddress.SetBytes(enote.OneTimeAddress[:]); err != nil {
		return ErrInvalidOneTimeAddress
	}
	var extensionG, extensionT curve25519.Scalar
	var nominalSpendPub curve25519.PublicKeyBytes

	var recoveredMainPub bool
	for _, mainAddressSpendPub := range mainAddressSpendPubs {
		// k^o_g = H_n("..g..", s^ctx_sr, C_a)
		makeCarrotSenderExtensionGCoinbase(&hasher, &extensionG, senderReceiverSecret, enote.Amount, mainAddressSpendPub)
		// k^o_t = H_n("..t..", s^ctx_sr, C_a)
		makeCarrotSenderExtensionTCoinbase(&hasher, &extensionT, senderReceiverSecret, enote.Amount, mainAddressSpendPub)

		var senderExtensionPubkey curve25519.VarTimePublicKey
		// K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_t T)
		senderExtensionPubkey.DoubleScalarBaseMultPrecomputed(&extensionT, crypto.GeneratorT, &extensionG)

		// K^j_s = Ko - K^o_ext
		nominalSpendPub = new(curve25519.VarTimePublicKey).Subtract(&oneTimeAddress, &senderExtensionPubkey).AsBytes()

		if nominalSpendPub == mainAddressSpendPub {
			recoveredMainPub = true
			break
		}
	}

	if !recoveredMainPub {
		return ErrMismatchedMainAddress
	}

	scan.SpendPub = nominalSpendPub
	scan.ExtensionG = extensionG
	scan.ExtensionT = extensionT

	// anchor = anchor_enc XOR m_anchor
	mask := makeAnchorEncryptionMask(&hasher, senderReceiverSecret, oneTimeAddress.AsBytes())
	subtle.XORBytes(scan.Randomness[:], enote.EncryptedAnchor.Slice(), mask[:])

	scan.Amount = enote.Amount
	scan.Type = EnoteTypePayment
	scan.AmountBlindingFactor = curve25519.PrivateKeyBytes{1}

	return nil
}

// TryScanEnoteChecked try_scan_carrot_enote_external_normal_checked
func (enote *EnoteV1) TryScanEnoteChecked(scan *ScanV1, inputContext []byte, encryptedPaymentId *[monero.PaymentIdSize]byte, senderReceiverUnctx curve25519.MontgomeryPoint, mainAddressSpendPubs ...curve25519.PublicKeyBytes) (err error) {
	var hasher blake2b.Digest

	// if vt' != vt, then FAIL
	nominalViewTag := makeViewTag(&hasher, senderReceiverUnctx, inputContext, enote.OneTimeAddress)
	if nominalViewTag != enote.ViewTag {
		// no match
		return ErrMismatchedViewTag
	}

	// s^ctx_sr = H_32(s_sr, D_e, input_context)
	senderReceiverSecret := MakeSenderReceiverSecret(&hasher, senderReceiverUnctx, enote.EphemeralPubKey, inputContext)

	var oneTimeAddress curve25519.VarTimePublicKey
	if _, err := oneTimeAddress.SetBytes(enote.OneTimeAddress[:]); err != nil {
		return ErrInvalidOneTimeAddress
	}

	scanNonCoinbaseInfo(&hasher, scan, &oneTimeAddress, enote.AmountCommitment, enote.EncryptedAnchor, encryptedPaymentId, senderReceiverSecret)

	var amountBlindingKey curve25519.Scalar
	scan.Amount, scan.Type, err = tryGetCarrotAmount[curve25519.VarTimeOperations](&hasher, &amountBlindingKey, senderReceiverSecret, enote.EncryptedAmount, enote.OneTimeAddress, scan.SpendPub, enote.AmountCommitment)
	if err != nil {
		return err
	}
	scan.AmountBlindingFactor = curve25519.PrivateKeyBytes(amountBlindingKey.Bytes())

	if !verifyNormalJanusProtectionAndConfirmPaymentId[curve25519.VarTimeOperations](&hasher, inputContext, scan.SpendPub, !slices.Contains(mainAddressSpendPubs, scan.SpendPub), enote.EphemeralPubKey, scan.Randomness, &scan.PaymentId) {
		return ErrJanusProtectionFailed
	}

	return nil
}

// scanNonCoinbaseInfo scan_non_coinbase_info
func scanNonCoinbaseInfo[T curve25519.PointOperations](hasher *blake2b.Digest,
	scan *ScanV1,
	oneTimeAddress *curve25519.PublicKey[T], amountCommitment curve25519.PublicKeyBytes,
	encryptedJanusAnchor [monero.JanusAnchorSize]byte, encryptedPaymentId *[monero.PaymentIdSize]byte, senderReceiverSecret types.Hash) {

	// K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_t T)
	{
		var senderExtensionPubkey curve25519.PublicKey[T]
		// k^o_g = H_n("..g..", s^ctx_sr, C_a)
		makeCarrotSenderExtensionG(hasher, &scan.ExtensionG, senderReceiverSecret, amountCommitment)

		// k^o_t = H_n("..t..", s^ctx_sr, C_a)
		makeCarrotSenderExtensionT(hasher, &scan.ExtensionT, senderReceiverSecret, amountCommitment)

		// K^o_ext = k^o_g G + k^o_t T
		senderExtensionPubkey.DoubleScalarBaseMultPrecomputed(&scan.ExtensionT, crypto.GeneratorT, &scan.ExtensionG)

		// K^j_s = Ko - K^o_ext
		scan.SpendPub = new(curve25519.PublicKey[T]).Subtract(oneTimeAddress, &senderExtensionPubkey).AsBytes()
	}

	if encryptedPaymentId != nil {
		// pid = pid_enc XOR m_pid, if applicable
		pidMask := makePaymentIdEncryptionMask(hasher, senderReceiverSecret, oneTimeAddress.AsBytes())
		subtle.XORBytes(scan.PaymentId[:], encryptedPaymentId[:], pidMask[:])
	} else {
		clear(scan.PaymentId[:])
	}

	// anchor = anchor_enc XOR m_anchor
	mask := makeAnchorEncryptionMask(hasher, senderReceiverSecret, oneTimeAddress.AsBytes())
	subtle.XORBytes(scan.Randomness[:], encryptedJanusAnchor[:], mask[:])
}

// tryGetCarrotAmount try_get_carrot_amount
func tryGetCarrotAmount[T curve25519.PointOperations](hasher *blake2b.Digest, amountBlindingKeyOut *curve25519.Scalar, senderReceiverSecret types.Hash, encryptedAmount [monero.EncryptedAmountSize]byte, oneTimeAddress curve25519.PublicKeyBytes, addressSpendPub curve25519.PublicKeyBytes, amountCommitment curve25519.PublicKeyBytes) (amount uint64, enoteType EnoteType, err error) {

	// a' = a_enc XOR m_a
	mask := makeAmountEncryptionMask(hasher, senderReceiverSecret, oneTimeAddress)
	subtle.XORBytes(encryptedAmount[:], encryptedAmount[:], mask[:])
	amount = binary.LittleEndian.Uint64(encryptedAmount[:])

	// if C_a ?= k_a' G + a' H, then PASS
	if tryRecomputeCarrotAmountCommitment[T](hasher, amountBlindingKeyOut, senderReceiverSecret, amount, addressSpendPub, EnoteTypePayment, amountCommitment) {
		return amount, EnoteTypePayment, nil
	}

	// if C_a ?= k_a' G + a' H, then PASS
	if tryRecomputeCarrotAmountCommitment[T](hasher, amountBlindingKeyOut, senderReceiverSecret, amount, addressSpendPub, EnoteTypeChange, amountCommitment) {
		return amount, EnoteTypeChange, nil
	}

	return amount, EnoteTypeChange, ErrMismatchedAmountCommitment

}

// tryRecomputeCarrotAmountCommitment try_recompute_carrot_amount_commitment
func tryRecomputeCarrotAmountCommitment[T curve25519.PointOperations](hasher *blake2b.Digest, amountBlindingKeyOut *curve25519.Scalar, senderReceiverSecret types.Hash, nominalAmount uint64, addressSpendPub curve25519.PublicKeyBytes, enoteType EnoteType, amountCommitment curve25519.PublicKeyBytes) bool {
	// k_a' = H_n(s^ctx_sr, a', K^j_s', enote_type')
	makeAmountBlindingFactor(hasher, amountBlindingKeyOut, senderReceiverSecret, nominalAmount, addressSpendPub, enoteType)

	nominalAmountCommitment := makeAmountCommitment[T](nominalAmount, amountBlindingKeyOut)

	return nominalAmountCommitment == amountCommitment
}

// verifyNormalJanusProtectionAndConfirmPaymentId verify_carrot_normal_janus_protection_and_confirm_pid
func verifyNormalJanusProtectionAndConfirmPaymentId[T curve25519.PointOperations](hasher *blake2b.Digest, inputContext []byte, nominalSpendPub curve25519.PublicKeyBytes, isSubaddress bool, ephemeralPub curve25519.MontgomeryPoint, nominalAnchor [monero.JanusAnchorSize]byte, nominalPaymentId *[monero.PaymentIdSize]byte) bool {
	// if can recompute D_e with pid', then PASS
	if verifyNormalJanusProtection[T](hasher, nominalAnchor, inputContext, nominalSpendPub, isSubaddress, *nominalPaymentId, ephemeralPub) {
		return true
	}

	// if it's already zero, FAIL
	if *nominalPaymentId == [monero.PaymentIdSize]byte{} {
		return false
	}

	// if can recompute D_e with null pid, then PASS
	clear(nominalPaymentId[:])
	return verifyNormalJanusProtection[T](hasher, nominalAnchor, inputContext, nominalSpendPub, isSubaddress, *nominalPaymentId, ephemeralPub)
}

// verifyNormalJanusProtection verify_carrot_normal_janus_protection
func verifyNormalJanusProtection[T curve25519.PointOperations](hasher *blake2b.Digest, nominalAnchor [monero.JanusAnchorSize]byte, inputContext []byte, nominalSpendPub curve25519.PublicKeyBytes, isSubaddress bool, nominalPaymentId [monero.PaymentIdSize]byte, ephemeralPub curve25519.MontgomeryPoint) bool {

	// d_e' = H_n(anchor_norm, input_context, K^j_s, pid))
	var ephemeralPrivateKey curve25519.Scalar
	makeEnoteEphemeralPrivateKey(hasher, &ephemeralPrivateKey, nominalAnchor[:], inputContext, nominalSpendPub, nominalPaymentId)

	// recompute D_e' for d_e' and address type
	if isSubaddress {
		var spendPub curve25519.PublicKey[T]
		if _, err := spendPub.SetBytes(nominalSpendPub[:]); err != nil {
			return false
		}

		// D_e' ?= D_e
		return ephemeralPub == MakeEnoteEphemeralPublicKeySubaddress(&ephemeralPrivateKey, &spendPub)
	} else {
		// D_e' ?= D_e
		return ephemeralPub == MakeEnoteEphemeralPublicKeyCryptonote[T](&ephemeralPrivateKey)
	}
}
