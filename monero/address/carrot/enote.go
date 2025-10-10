package carrot

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

type CoinbaseEnoteV1 struct {
	// OneTimeAddress K_o
	OneTimeAddress crypto.PublicKeyBytes `json:"one_time_address"`
	Amount         uint64                `json:"amount"`

	// EncryptedAnchor carrot janus anchor XORd with a user-defined secret
	EncryptedAnchor [monero.JanusAnchorSize]byte `json:"encrypted_anchor"`
	ViewTag         [3]byte                      `json:"view_tag"`

	// EphemeralPubKey D_e
	EphemeralPubKey crypto.X25519PublicKey `json:"ephemeral_pub_key"`

	BlockIndex uint64 `json:"block_index"`
}
type EnoteType uint8

const (
	EnoteTypePayment = EnoteType(iota)
	EnoteTypeChange
)

// makeEnoteEphemeralPrivateKey make_carrot_enote_ephemeral_privkey
func makeEnoteEphemeralPrivateKey(hasher *blake2b.Digest, ephemeralPrivateKeyOut *crypto.PrivateKeyScalar, anchor, inputContext []byte, spendPub crypto.PublicKeyBytes, paymentId [8]byte) {
	// k_e = (H_64(anchor_norm, input_context, K^j_s, pid)) mod l
	ScalarTranscript(
		ephemeralPrivateKeyOut.Scalar(), hasher, nil,
		[]byte(DomainSeparatorEphemeralPrivateKey), anchor, inputContext, spendPub[:], paymentId[:],
	)
}

// makeEnoteEphemeralPublicKeySubaddress make_carrot_enote_ephemeral_pubkey_subaddress
func makeEnoteEphemeralPublicKeySubaddress(key *crypto.PrivateKeyScalar, spendKey *crypto.PublicKeyPoint) (out crypto.X25519PublicKey) {
	// K_e = d_e K^j_s
	K_e := new(edwards25519.Point).UnsafeVarTimeScalarMult(key.Scalar(), spendKey.Point())

	// D_e = ConvertPointE(K_e)
	return crypto.ConvertPointE(K_e)
}

// makeEnoteEphemeralPublicKeyCryptonote make_carrot_enote_ephemeral_pubkey_cryptonote
func makeEnoteEphemeralPublicKeyCryptonote(key *crypto.PrivateKeyScalar) (out crypto.X25519PublicKey) {
	// D_e = d_e B
	crypto.X25519ScalarBaseMult(&out, key.Scalar())

	return out
}

// makeUncontextualizedSharedKeyReceiver make_carrot_uncontextualized_shared_key_receiver
func makeUncontextualizedSharedKeyReceiver(viewPriv crypto.PrivateKeyBytes, ephemeralPubKey crypto.X25519PublicKey) (senderReceiverUnctx crypto.X25519PublicKey) {
	crypto.X25519ScalarMult(&senderReceiverUnctx, viewPriv, ephemeralPubKey)
	return senderReceiverUnctx
}

// makeUncontextualizedSharedKeySender make_carrot_uncontextualized_shared_key_sender
func makeUncontextualizedSharedKeySender(ephemeralPrivKey crypto.PrivateKeyBytes, viewPub *crypto.PublicKeyPoint) (senderReceiverUnctx crypto.X25519PublicKey) {
	// if K^j_v not in prime order subgroup, then FAIL
	if viewPub == nil || !viewPub.IsTorsionFree() {
		return crypto.ZeroX25519PublicKey
	}

	// s_sr = d_e * ConvertPointE(K^j_v)
	viewPubkeyX25519 := crypto.ConvertPointE(viewPub.Point())
	crypto.X25519ScalarMult(&senderReceiverUnctx, ephemeralPrivKey, viewPubkeyX25519)
	return senderReceiverUnctx
}

// makeSenderReceiverSecret make_carrot_sender_receiver_secret
func makeSenderReceiverSecret(hasher *blake2b.Digest, senderReceiverUnctx, ephemeralPubKey crypto.X25519PublicKey, inputContext []byte) (out types.Hash) {
	// 1. s^ctx_sr = H_32(s_sr, D_e, input_context)
	HashedTranscript(
		out[:], hasher, senderReceiverUnctx[:],
		[]byte(DomainSeparatorSenderReceiverSecret), ephemeralPubKey[:], inputContext,
	)
	return out
}

// makeAmountBlindingFactor make_carrot_amount_blinding_factor
func makeAmountBlindingFactor(hasher *blake2b.Digest, amountBlindingKeyOut *crypto.PrivateKeyScalar, secretSenderReceiver types.Hash, amount uint64, spendPub crypto.PublicKeyBytes, enoteType EnoteType) {
	// k_a = H_n(s^ctx_sr, a, K^j_s, enote_type)
	var amountBytes [8]byte
	binary.LittleEndian.PutUint64(amountBytes[:], amount)
	ScalarTranscript(
		amountBlindingKeyOut.Scalar(), hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorAmountBlindingFactor), amountBytes[:], spendPub[:], []byte{byte(enoteType)},
	)
}

// makeAmountCommitment make_carrot_amount_commitment
func makeAmountCommitment(amount uint64, amountBlindingFactor *crypto.PrivateKeyScalar) crypto.PublicKeyBytes {
	var amountCommitment crypto.PublicKeyPoint
	crypto.RctCommit(&amountCommitment, amount, amountBlindingFactor)
	return amountCommitment.AsBytes()
}

// makeOnetimeAddress make_carrot_onetime_address
func makeOnetimeAddress(hasher *blake2b.Digest, spendPub *crypto.PublicKeyPoint, secretSenderReceiver types.Hash, amountCommitment crypto.PublicKeyBytes) crypto.PublicKeyBytes {
	var senderExtensionPubkey crypto.PublicKeyPoint
	// K^o_ext = k^o_g G + k^o_t T
	// make_carrot_onetime_address_extension_pubkey
	{
		var senderExtensionG, senderExtensionT edwards25519.Scalar
		// k^o_g = H_n("..g..", s^ctx_sr, C_a)
		// make_carrot_onetime_address_extension_g
		ScalarTranscript(
			&senderExtensionG, hasher, secretSenderReceiver[:],
			[]byte(DomainSeparatorOneTimeExtensionG), amountCommitment[:],
		)

		// k^o_t = H_n("..t..", s^ctx_sr, C_a)
		// make_carrot_onetime_address_extension_t
		ScalarTranscript(
			&senderExtensionT, hasher, secretSenderReceiver[:],
			[]byte(DomainSeparatorOneTimeExtensionT), amountCommitment[:],
		)

		// K^o_ext = k^o_g G + k^o_t T
		senderExtensionPubkey.Point().VarTimeDoubleScalarBaseMult(&senderExtensionT, crypto.GeneratorT, &senderExtensionG)
	}

	// Ko = K^j_s + K^o_ext
	return spendPub.Add(&senderExtensionPubkey).AsBytes()
}

// makeViewTag make_carrot_view_tag
func makeViewTag(hasher *blake2b.Digest, senderReceiverUnctx crypto.X25519PublicKey, inputContext []byte, oneTimeAddress crypto.PublicKeyBytes) (out [monero.CarrotViewTagSize]byte) {
	// vt = H_3(s_sr || input_context || Ko)

	HashedTranscript(
		out[:], hasher, senderReceiverUnctx[:],
		[]byte(DomainSeparatorViewTag), inputContext, oneTimeAddress[:],
	)
	return out
}

// makeAnchorEncryptionMask make_carrot_anchor_encryption_mask
func makeAnchorEncryptionMask(hasher *blake2b.Digest, secretSenderReceiver types.Hash, oneTimeAddress crypto.PublicKeyBytes) (out [monero.JanusAnchorSize]byte) {
	// m_anchor = H_16(s^ctx_sr, Ko)
	HashedTranscript(
		out[:], hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorEncryptionMaskAnchor), oneTimeAddress[:],
	)
	return out
}

// makeAmountEncryptionMask make_carrot_amount_encryption_mask
func makeAmountEncryptionMask(hasher *blake2b.Digest, secretSenderReceiver types.Hash, oneTimeAddress crypto.PublicKeyBytes) (out [monero.EncryptedAmountSize]byte) {
	// m_a = H_8(s^ctx_sr, Ko)
	HashedTranscript(
		out[:], hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorEncryptionMaskAmount), oneTimeAddress[:],
	)
	return out
}

// makePaymentIdEncryptionMask make_carrot_payment_id_encryption_mask
func makePaymentIdEncryptionMask(hasher *blake2b.Digest, secretSenderReceiver types.Hash, oneTimeAddress crypto.PublicKeyBytes) (out [monero.PaymentIdSize]byte) {
	// m_pid = H_8(s^ctx_sr, Ko)
	HashedTranscript(
		out[:], hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorEncryptionMaskPaymentId), oneTimeAddress[:],
	)
	return out
}

// makeJanusAnchorSpecial make_carrot_janus_anchor_special
func makeJanusAnchorSpecial(hasher *blake2b.Digest, ephemeralPubKey crypto.X25519PublicKey, inputContext []byte, oneTimeAddress crypto.PublicKeyBytes, viewSecret crypto.PrivateKeyBytes) (out [monero.JanusAnchorSize]byte) {
	// anchor_sp = H_16(D_e, input_context, Ko, k_v)
	HashedTranscript(
		out[:], hasher, viewSecret[:],
		[]byte(DomainSeparatorJanusAnchorSpecial), ephemeralPubKey[:], inputContext, oneTimeAddress[:],
	)
	return out
}
