package carrot

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

type ScanV1 struct {
	Type                 EnoteType
	Amount               uint64
	AmountBlindingFactor crypto.PrivateKeyBytes

	ExtensionG crypto.PrivateKeyScalar
	ExtensionT crypto.PrivateKeyScalar
	SpendPub   crypto.PublicKeyBytes

	Randomness [monero.JanusAnchorSize]byte

	PaymentId [monero.PaymentIdSize]byte
}

var ErrMismatchedViewTag = errors.New("mismatched view tag")
var ErrMismatchedMainAddress = errors.New("mismatched main address")
var ErrJanusProtectionFailed = errors.New("janus protection check failed")
var ErrMismatchedAmountCommitment = errors.New("mismatched amount commitment")

// TryScanEnoteChecked try_scan_carrot_coinbase_enote_checked
func (enote *CoinbaseEnoteV1) TryScanEnoteChecked(scan *ScanV1, inputContext []byte, senderReceiverUnctx crypto.X25519PublicKey, mainAddressSpendPub crypto.PublicKeyBytes) error {
	var hasher blake2b.Digest

	// if vt' != vt, then FAIL
	nominalViewTag := makeViewTag(&hasher, senderReceiverUnctx, inputContext[:], enote.OneTimeAddress)
	if nominalViewTag != enote.ViewTag {
		// no match
		return ErrMismatchedViewTag
	}

	// s^ctx_sr = H_32(s_sr, D_e, input_context)
	senderReceiverSecret := makeSenderReceiverSecret(&hasher, senderReceiverUnctx, enote.EphemeralPubKey, inputContext)

	amountCommitment := makeAmountCommitmentCoinbase(enote.Amount)

	scanDestInfo(&hasher, scan, enote.OneTimeAddress, amountCommitment, enote.EncryptedAnchor, nil, senderReceiverSecret)

	if mainAddressSpendPub != scan.SpendPub {
		return ErrMismatchedMainAddress
	}

	if !verifyNormalJanusProtection(&hasher, scan.Randomness, inputContext, scan.SpendPub, false, [monero.PaymentIdSize]byte{}, enote.EphemeralPubKey) {
		return ErrJanusProtectionFailed
	}

	scan.Amount = enote.Amount
	scan.Type = EnoteTypePayment
	scan.AmountBlindingFactor = crypto.PrivateKeyBytes{1}

	return nil
}

// TryScanEnoteChecked try_scan_carrot_enote_external_normal_checked
func (enote *EnoteV1) TryScanEnoteChecked(scan *ScanV1, inputContext []byte, senderReceiverUnctx crypto.X25519PublicKey, mainAddressSpendPub crypto.PublicKeyBytes) (err error) {
	var hasher blake2b.Digest

	// if vt' != vt, then FAIL
	nominalViewTag := makeViewTag(&hasher, senderReceiverUnctx, inputContext[:], enote.OneTimeAddress)
	if nominalViewTag != enote.ViewTag {
		// no match
		return ErrMismatchedViewTag
	}

	// s^ctx_sr = H_32(s_sr, D_e, input_context)
	senderReceiverSecret := makeSenderReceiverSecret(&hasher, senderReceiverUnctx, enote.EphemeralPubKey, inputContext)

	// TODO: payment id
	scanDestInfo(&hasher, scan, enote.OneTimeAddress, enote.AmountCommitment, enote.EncryptedAnchor, nil, senderReceiverSecret)

	var amountBlindingKey crypto.PrivateKeyScalar
	scan.Amount, scan.Type, err = tryGetCarrotAmount(&hasher, &amountBlindingKey, senderReceiverSecret, enote.EncryptedAmount, enote.OneTimeAddress, scan.SpendPub, enote.AmountCommitment)
	if err != nil {
		return err
	}
	scan.AmountBlindingFactor = amountBlindingKey.AsBytes()

	// todo: payment id!
	if !verifyNormalJanusProtection(&hasher, scan.Randomness, inputContext, scan.SpendPub, scan.SpendPub != mainAddressSpendPub, [monero.PaymentIdSize]byte{}, enote.EphemeralPubKey) {
		return ErrJanusProtectionFailed
	}

	return nil
}

// scanDestInfo scan_carrot_dest_info
func scanDestInfo(hasher *blake2b.Digest,
	scan *ScanV1,
	oneTimeAddress crypto.PublicKeyBytes, amountCommitment crypto.PublicKeyBytes,
	encryptedJanusAnchor [monero.JanusAnchorSize]byte, encryptedPaymentId *[monero.PaymentIdSize]byte, senderReceiverSecret types.Hash) {
	var senderExtensionPubkey edwards25519.Point
	// K^o_ext = k^o_g G + k^o_t T
	// make_carrot_onetime_address_extension_pubkey
	{
		makeCarrotOnetimeAddressExtensionG(hasher, scan.ExtensionG.Scalar(), senderReceiverSecret, amountCommitment)
		makeCarrotOnetimeAddressExtensionT(hasher, scan.ExtensionT.Scalar(), senderReceiverSecret, amountCommitment)

		// K^o_ext = k^o_g G + k^o_t T
		senderExtensionPubkey.UnsafeVarTimeDoubleScalarBaseMultPrecomputed(scan.ExtensionT.Scalar(), generatorTPrecomputedTable, scan.ExtensionG.Scalar())
	}

	// K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_t T)
	scan.SpendPub = oneTimeAddress.AsPoint().Subtract(crypto.PublicKeyFromPoint(&senderExtensionPubkey)).AsBytes()

	if encryptedPaymentId != nil {
		// 5. pid_enc = pid XOR m_pid
		pidMask := makePaymentIdEncryptionMask(hasher, senderReceiverSecret, oneTimeAddress)
		subtle.XORBytes(scan.PaymentId[:], encryptedPaymentId[:], pidMask[:])
	}

	// anchor = anchor_enc XOR m_anchor
	mask := makeAnchorEncryptionMask(hasher, senderReceiverSecret, oneTimeAddress)
	subtle.XORBytes(scan.Randomness[:], encryptedJanusAnchor[:], mask[:])
}

// tryGetCarrotAmount try_get_carrot_amount
func tryGetCarrotAmount(hasher *blake2b.Digest, amountBlindingKeyOut *crypto.PrivateKeyScalar, senderReceiverSecret types.Hash, encryptedAmount [monero.EncryptedAmountSize]byte, oneTimeAddress crypto.PublicKeyBytes, addressSpendPub crypto.PublicKeyBytes, amountCommitment crypto.PublicKeyBytes) (amount uint64, enoteType EnoteType, err error) {

	// a' = a_enc XOR m_a
	mask := makeAmountEncryptionMask(hasher, senderReceiverSecret, oneTimeAddress)
	subtle.XORBytes(encryptedAmount[:], encryptedAmount[:], mask[:])
	amount = binary.LittleEndian.Uint64(encryptedAmount[:])

	// if C_a ?= k_a' G + a' H, then PASS
	if tryRecomputeCarrotAmountCommitment(hasher, amountBlindingKeyOut, senderReceiverSecret, amount, addressSpendPub, EnoteTypePayment, amountCommitment) {
		return amount, EnoteTypePayment, nil
	}

	// if C_a ?= k_a' G + a' H, then PASS
	if tryRecomputeCarrotAmountCommitment(hasher, amountBlindingKeyOut, senderReceiverSecret, amount, addressSpendPub, EnoteTypeChange, amountCommitment) {
		return amount, EnoteTypeChange, nil
	}

	return amount, EnoteTypeChange, ErrMismatchedAmountCommitment

}

// tryRecomputeCarrotAmountCommitment try_recompute_carrot_amount_commitment
func tryRecomputeCarrotAmountCommitment(hasher *blake2b.Digest, amountBlindingKeyOut *crypto.PrivateKeyScalar, senderReceiverSecret types.Hash, nominalAmount uint64, addressSpendPub crypto.PublicKeyBytes, enoteType EnoteType, amountCommitment crypto.PublicKeyBytes) bool {
	// k_a' = H_n(s^ctx_sr, a', K^j_s', enote_type')
	makeAmountBlindingFactor(hasher, amountBlindingKeyOut, senderReceiverSecret, nominalAmount, addressSpendPub, enoteType)

	nominalAmountCommitment := makeAmountCommitment(nominalAmount, amountBlindingKeyOut)

	return nominalAmountCommitment == amountCommitment
}

// verifyNormalJanusProtection verify_carrot_normal_janus_protection
func verifyNormalJanusProtection(hasher *blake2b.Digest, nominalAnchor [monero.JanusAnchorSize]byte, inputContext []byte, nominalSpendPub crypto.PublicKeyBytes, isSubaddress bool, nominalPaymentId [monero.PaymentIdSize]byte, ephemeralPub crypto.X25519PublicKey) bool {

	// d_e' = H_n(anchor_norm, input_context, K^j_s, pid))
	var ephemeralPrivateKey crypto.PrivateKeyScalar
	makeEnoteEphemeralPrivateKey(hasher, &ephemeralPrivateKey, nominalAnchor[:], inputContext, nominalSpendPub, nominalPaymentId)

	// recompute D_e' for d_e' and address type
	if isSubaddress {
		// D_e' ?= D_e
		return ephemeralPub == makeEnoteEphemeralPublicKeySubaddress(&ephemeralPrivateKey, nominalSpendPub.AsPoint())
	} else {
		// D_e' ?= D_e
		return ephemeralPub == makeEnoteEphemeralPublicKeyCryptonote(&ephemeralPrivateKey)
	}
}
