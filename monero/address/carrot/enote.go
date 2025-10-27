package carrot

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type CoinbaseEnoteV1 struct {
	// OneTimeAddress K_o
	OneTimeAddress curve25519.PublicKeyBytes `json:"one_time_address"`
	Amount         uint64                    `json:"amount"`

	// EncryptedAnchor carrot janus anchor XORd with a user-defined secret
	EncryptedAnchor [monero.JanusAnchorSize]byte   `json:"encrypted_anchor"`
	ViewTag         [monero.CarrotViewTagSize]byte `json:"view_tag"`

	// EphemeralPubKey D_e
	EphemeralPubKey curve25519.MontgomeryPoint `json:"ephemeral_pub_key"`

	BlockIndex uint64 `json:"block_index"`
}

type RCTEnoteProposal struct {
	Enote                EnoteV1                    `json:"enote"`
	Amount               uint64                     `json:"amount"`
	AmountBlindingFactor curve25519.PrivateKeyBytes `json:"amount_blinding_factor"`
	EncryptedPaymentId   [monero.PaymentIdSize]byte `json:"encrypted_payment_id"`
}

type EnoteV1 struct {
	// OneTimeAddress K_o
	OneTimeAddress curve25519.PublicKeyBytes `json:"one_time_address"`
	// AmountCommitment C_a
	AmountCommitment curve25519.PublicKeyBytes        `json:"amount_commitment"`
	EncryptedAmount  [monero.EncryptedAmountSize]byte `json:"encrypted_amount"`

	// EncryptedAnchor carrot janus anchor XORd with a user-defined secret
	EncryptedAnchor [monero.JanusAnchorSize]byte   `json:"encrypted_anchor"`
	ViewTag         [monero.CarrotViewTagSize]byte `json:"view_tag"`

	// EphemeralPubKey D_e
	EphemeralPubKey curve25519.MontgomeryPoint `json:"ephemeral_pub_key"`

	FirstKeyImage curve25519.PublicKeyBytes `json:"tx_first_key_image"`
}

type EnoteType uint8

const (
	EnoteTypePayment = EnoteType(iota)
	EnoteTypeChange
)

// makeEnoteEphemeralPrivateKey make_carrot_enote_ephemeral_privkey
func makeEnoteEphemeralPrivateKey(hasher *blake2b.Digest, ephemeralPrivateKeyOut *curve25519.Scalar, anchor, inputContext []byte, spendPub curve25519.PublicKeyBytes, paymentId [8]byte) {
	// k_e = (H_64(anchor_norm, input_context, K^j_s, pid)) mod l
	ScalarTranscript(
		ephemeralPrivateKeyOut, hasher, nil,
		[]byte(DomainSeparatorEphemeralPrivateKey), anchor, inputContext, spendPub[:], paymentId[:],
	)
}

// makeEnoteEphemeralPublicKeySubaddress make_carrot_enote_ephemeral_pubkey_subaddress
// Precondition: spendPub is torsion free
func makeEnoteEphemeralPublicKeySubaddress[T curve25519.PointOperations](key *curve25519.Scalar, spendKey *curve25519.PublicKey[T]) (out curve25519.MontgomeryPoint) {
	// K_e = d_e K^j_s
	var K_e curve25519.PublicKey[T]
	// D_e = ConvertPointE(K_e)
	return K_e.ScalarMult(key, spendKey).Montgomery()
}

// makeEnoteEphemeralPublicKeyCryptonote make_carrot_enote_ephemeral_pubkey_cryptonote
func makeEnoteEphemeralPublicKeyCryptonote[T curve25519.PointOperations](key *curve25519.Scalar) (out curve25519.MontgomeryPoint) {
	// D_e = d_e B
	curve25519.MontgomeryScalarBaseMult[T](&out, key)

	return out
}

// MakeUncontextualizedSharedKeyReceiver make_carrot_uncontextualized_shared_key_receiver
func MakeUncontextualizedSharedKeyReceiver(viewPriv *curve25519.Scalar, ephemeralPubKey *curve25519.MontgomeryPoint) (senderReceiverUnctx curve25519.MontgomeryPoint) {
	senderReceiverUnctx.ScalarMult(viewPriv, ephemeralPubKey)
	return senderReceiverUnctx
}

// makeUncontextualizedSharedKeySender make_carrot_uncontextualized_shared_key_sender
// Precondition: viewPub is torsion free
func makeUncontextualizedSharedKeySender[T curve25519.PointOperations](ephemeralPrivKey *curve25519.Scalar, viewPub *curve25519.PublicKey[T]) (senderReceiverUnctx curve25519.MontgomeryPoint) {
	// s_sr = d_e ConvertPointE(K^j_v)
	viewPubkeyX25519 := viewPub.Montgomery()
	senderReceiverUnctx.ScalarMult(ephemeralPrivKey, &viewPubkeyX25519)
	return senderReceiverUnctx
}

// makeUncontextualizedSharedKeySenderVarTime
// VarTime implementation of makeUncontextualizedSharedKeySender
func makeUncontextualizedSharedKeySenderVarTime[T curve25519.PointOperations](ephemeralPrivKey *curve25519.Scalar, viewPub *curve25519.PublicKey[T]) (senderReceiverUnctx curve25519.MontgomeryPoint) {
	// s_sr = ConvertPointE(d_e * K^j_v)
	var tmp curve25519.PublicKey[T]
	return tmp.ScalarMult(ephemeralPrivKey, viewPub).Montgomery()
}

// makeSenderReceiverSecret make_carrot_sender_receiver_secret
func makeSenderReceiverSecret(hasher *blake2b.Digest, senderReceiverUnctx, ephemeralPubKey curve25519.MontgomeryPoint, inputContext []byte) (out types.Hash) {
	// 1. s^ctx_sr = H_32(s_sr, D_e, input_context)
	HashedTranscript(
		out[:], hasher, senderReceiverUnctx[:],
		[]byte(DomainSeparatorSenderReceiverSecret), ephemeralPubKey[:], inputContext,
	)
	return out
}

// makeAmountBlindingFactor make_carrot_amount_blinding_factor
func makeAmountBlindingFactor(hasher *blake2b.Digest, amountBlindingKeyOut *curve25519.Scalar, secretSenderReceiver types.Hash, amount uint64, spendPub curve25519.PublicKeyBytes, enoteType EnoteType) {
	// k_a = H_n(s^ctx_sr, a, K^j_s, enote_type)
	var amountBytes [8]byte
	binary.LittleEndian.PutUint64(amountBytes[:], amount)
	ScalarTranscript(
		amountBlindingKeyOut, hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorAmountBlindingFactor), amountBytes[:], spendPub[:], []byte{byte(enoteType)},
	)
}

// makeAmountCommitment make_carrot_amount_commitment
func makeAmountCommitment[T curve25519.PointOperations](amount uint64, amountBlindingFactor *curve25519.Scalar) curve25519.PublicKeyBytes {
	var amountCommitment curve25519.PublicKey[T]
	crypto.RctCommit(&amountCommitment, amount, amountBlindingFactor)
	return amountCommitment.Bytes()
}

var coinbaseAmountBlindingFactor = new(curve25519.Point).ScalarBaseMult((&curve25519.PrivateKeyBytes{1}).Scalar())

// makeAmountCommitmentCoinbase Specialized implementation with baked in blinding factor
// this is faster than makeAmountCommitment, but is specific only for coinbase (as it uses a fixed amount blinding key)
func makeAmountCommitmentCoinbase[T curve25519.PointOperations](amount uint64) curve25519.PublicKeyBytes {

	var amountBytes curve25519.PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountBytes[:], amount)

	// no reduction is necessary: amountBytes is always lesser than l
	var amountK curve25519.Scalar
	_, _ = amountK.SetCanonicalBytes(amountBytes[:])

	var amountCommitment curve25519.PublicKey[T]
	amountCommitment.ScalarMultPrecomputed(&amountK, crypto.GeneratorH)
	amountCommitment.Add(&amountCommitment, curve25519.FromPoint[T](coinbaseAmountBlindingFactor))

	return amountCommitment.Bytes()
}

// makeOnetimeAddress make_carrot_onetime_address
func makeOnetimeAddress[T curve25519.PointOperations](hasher *blake2b.Digest, spendPub *curve25519.PublicKey[T], secretSenderReceiver types.Hash, amountCommitment curve25519.PublicKeyBytes) curve25519.PublicKeyBytes {
	var senderExtensionPubkey curve25519.PublicKey[T]
	// K^o_ext = k^o_g G + k^o_t T
	// make_carrot_onetime_address_extension_pubkey
	{
		var senderExtensionG, senderExtensionT curve25519.Scalar
		makeCarrotOnetimeAddressExtensionG(hasher, &senderExtensionG, secretSenderReceiver, amountCommitment)
		makeCarrotOnetimeAddressExtensionT(hasher, &senderExtensionT, secretSenderReceiver, amountCommitment)

		// K^o_ext = k^o_g G + k^o_t T
		senderExtensionPubkey.DoubleScalarBaseMultPrecomputed(&senderExtensionT, crypto.GeneratorT, &senderExtensionG)
	}

	// Ko = K^j_s + K^o_ext
	var Ko curve25519.PublicKey[T]
	Ko.Add(spendPub, &senderExtensionPubkey)
	return Ko.Bytes()
}

// makeViewTag make_carrot_view_tag
func makeViewTag(hasher *blake2b.Digest, senderReceiverUnctx curve25519.MontgomeryPoint, inputContext []byte, oneTimeAddress curve25519.PublicKeyBytes) (out [monero.CarrotViewTagSize]byte) {
	// vt = H_3(s_sr || input_context || Ko)

	HashedTranscript(
		out[:], hasher, senderReceiverUnctx[:],
		[]byte(DomainSeparatorViewTag), inputContext, oneTimeAddress[:],
	)
	return out
}

// makeAnchorEncryptionMask make_carrot_anchor_encryption_mask
func makeAnchorEncryptionMask(hasher *blake2b.Digest, secretSenderReceiver types.Hash, oneTimeAddress curve25519.PublicKeyBytes) (out [monero.JanusAnchorSize]byte) {
	// m_anchor = H_16(s^ctx_sr, Ko)
	HashedTranscript(
		out[:], hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorEncryptionMaskAnchor), oneTimeAddress[:],
	)
	return out
}

// makeAmountEncryptionMask make_carrot_amount_encryption_mask
func makeAmountEncryptionMask(hasher *blake2b.Digest, secretSenderReceiver types.Hash, oneTimeAddress curve25519.PublicKeyBytes) (out [monero.EncryptedAmountSize]byte) {
	// m_a = H_8(s^ctx_sr, Ko)
	HashedTranscript(
		out[:], hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorEncryptionMaskAmount), oneTimeAddress[:],
	)
	return out
}

// makePaymentIdEncryptionMask make_carrot_payment_id_encryption_mask
func makePaymentIdEncryptionMask(hasher *blake2b.Digest, secretSenderReceiver types.Hash, oneTimeAddress curve25519.PublicKeyBytes) (out [monero.PaymentIdSize]byte) {
	// m_pid = H_8(s^ctx_sr, Ko)
	HashedTranscript(
		out[:], hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorEncryptionMaskPaymentId), oneTimeAddress[:],
	)
	return out
}

// makeJanusAnchorSpecial make_carrot_janus_anchor_special
func makeJanusAnchorSpecial(hasher *blake2b.Digest, ephemeralPubKey curve25519.MontgomeryPoint, inputContext []byte, oneTimeAddress curve25519.PublicKeyBytes, viewSecret curve25519.PrivateKeyBytes) (out [monero.JanusAnchorSize]byte) {
	// anchor_sp = H_16(D_e, input_context, Ko, k_v)
	HashedTranscript(
		out[:], hasher, viewSecret[:],
		[]byte(DomainSeparatorJanusAnchorSpecial), ephemeralPubKey[:], inputContext, oneTimeAddress[:],
	)
	return out
}

// makeCarrotOnetimeAddressExtensionG make_carrot_onetime_address_extension_g
func makeCarrotOnetimeAddressExtensionG(hasher *blake2b.Digest, extensionOut *curve25519.Scalar, secretSenderReceiver types.Hash, amountCommitment curve25519.PublicKeyBytes) {
	// k^o_g = H_n("..g..", s^ctx_sr, C_a)
	ScalarTranscript(
		extensionOut, hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorOneTimeExtensionG), amountCommitment[:],
	)
}

// makeCarrotOnetimeAddressExtensionT make_carrot_onetime_address_extension_t
func makeCarrotOnetimeAddressExtensionT(hasher *blake2b.Digest, extensionOut *curve25519.Scalar, secretSenderReceiver types.Hash, amountCommitment curve25519.PublicKeyBytes) {
	// k^o_t = H_n("..t..", s^ctx_sr, C_a)
	ScalarTranscript(
		extensionOut, hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorOneTimeExtensionT), amountCommitment[:],
	)
}
