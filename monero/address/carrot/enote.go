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
	EncryptedAnchor [monero.JanusAnchorSize]byte   `json:"encrypted_anchor"`
	ViewTag         [monero.CarrotViewTagSize]byte `json:"view_tag"`

	// EphemeralPubKey D_e
	EphemeralPubKey crypto.X25519PublicKey `json:"ephemeral_pub_key"`

	BlockIndex uint64 `json:"block_index"`
}

type RCTEnoteProposal struct {
	Enote                EnoteV1                    `json:"enote"`
	Amount               uint64                     `json:"amount"`
	AmountBlindingFactor crypto.PrivateKeyBytes     `json:"amount_blinding_factor"`
	EncryptedPaymentId   [monero.PaymentIdSize]byte `json:"encrypted_payment_id"`
}

type EnoteV1 struct {
	// OneTimeAddress K_o
	OneTimeAddress crypto.PublicKeyBytes `json:"one_time_address"`
	// AmountCommitment C_a
	AmountCommitment crypto.PublicKeyBytes            `json:"amount_commitment"`
	EncryptedAmount  [monero.EncryptedAmountSize]byte `json:"encrypted_amount"`

	// EncryptedAnchor carrot janus anchor XORd with a user-defined secret
	EncryptedAnchor [monero.JanusAnchorSize]byte   `json:"encrypted_anchor"`
	ViewTag         [monero.CarrotViewTagSize]byte `json:"view_tag"`

	// EphemeralPubKey D_e
	EphemeralPubKey crypto.X25519PublicKey `json:"ephemeral_pub_key"`

	FirstKeyImage crypto.PublicKeyBytes `json:"tx_first_key_image"`
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
// Precondition: spendPub is torsion free
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

// MakeUncontextualizedSharedKeyReceiver make_carrot_uncontextualized_shared_key_receiver
func MakeUncontextualizedSharedKeyReceiver(viewPriv crypto.PrivateKeyBytes, ephemeralPubKey crypto.X25519PublicKey) (senderReceiverUnctx crypto.X25519PublicKey) {
	crypto.X25519ScalarMult(&senderReceiverUnctx, viewPriv, ephemeralPubKey)
	return senderReceiverUnctx
}

// makeUncontextualizedSharedKeySender make_carrot_uncontextualized_shared_key_sender
// Precondition: viewPub is torsion free
func makeUncontextualizedSharedKeySender(ephemeralPrivKey crypto.PrivateKeyBytes, viewPub *crypto.PublicKeyPoint) (senderReceiverUnctx crypto.X25519PublicKey) {
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

var coinbaseAmountBlindingFactor = (&crypto.PrivateKeyBytes{1}).PublicKey().AsPoint().Point()

var generatorHPrecomputedTable = edwards25519.PointTablePrecompute(crypto.GeneratorH)

// makeAmountCommitmentCoinbase Specialized implementation with baked in blinding factor
// this is faster than makeAmountCommitment, but is specific only for coinbase (as it uses a fixed amount blinding key)
func makeAmountCommitmentCoinbase(amount uint64) crypto.PublicKeyBytes {

	var amountBytes crypto.PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountBytes[:], amount)

	// no reduction is necessary: amountBytes is always lesser than l
	var amountK edwards25519.Scalar
	_, _ = amountK.SetCanonicalBytes(amountBytes[:])

	var amountCommitment edwards25519.Point
	amountCommitment.UnsafeVarTimeScalarMultPrecomputed(&amountK, generatorHPrecomputedTable)
	amountCommitment.Add(&amountCommitment, coinbaseAmountBlindingFactor)

	return crypto.PublicKeyBytes(amountCommitment.Bytes())
}

var generatorTPrecomputedTable = edwards25519.PointTablePrecompute(crypto.GeneratorT)

// makeOnetimeAddress make_carrot_onetime_address
func makeOnetimeAddress(hasher *blake2b.Digest, spendPub *crypto.PublicKeyPoint, secretSenderReceiver types.Hash, amountCommitment crypto.PublicKeyBytes) crypto.PublicKeyBytes {
	var senderExtensionPubkey edwards25519.Point
	// K^o_ext = k^o_g G + k^o_t T
	// make_carrot_onetime_address_extension_pubkey
	{
		var senderExtensionG, senderExtensionT edwards25519.Scalar
		makeCarrotOnetimeAddressExtensionG(hasher, &senderExtensionG, secretSenderReceiver, amountCommitment)
		makeCarrotOnetimeAddressExtensionT(hasher, &senderExtensionT, secretSenderReceiver, amountCommitment)

		// K^o_ext = k^o_g G + k^o_t T
		// senderExtensionPubkey.Point().VarTimeDoubleScalarBaseMult(&senderExtensionT, crypto.GeneratorT, &senderExtensionG)
		senderExtensionPubkey.UnsafeVarTimeDoubleScalarBaseMultPrecomputed(&senderExtensionT, generatorTPrecomputedTable, &senderExtensionG)
	}

	// Ko = K^j_s + K^o_ext
	return spendPub.Add(crypto.PublicKeyFromPoint(&senderExtensionPubkey)).AsBytes()
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

// makeCarrotOnetimeAddressExtensionG make_carrot_onetime_address_extension_g
func makeCarrotOnetimeAddressExtensionG(hasher *blake2b.Digest, extensionOut *edwards25519.Scalar, secretSenderReceiver types.Hash, amountCommitment crypto.PublicKeyBytes) {
	// k^o_g = H_n("..g..", s^ctx_sr, C_a)
	ScalarTranscript(
		extensionOut, hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorOneTimeExtensionG), amountCommitment[:],
	)
}

// makeCarrotOnetimeAddressExtensionT make_carrot_onetime_address_extension_t
func makeCarrotOnetimeAddressExtensionT(hasher *blake2b.Digest, extensionOut *edwards25519.Scalar, secretSenderReceiver types.Hash, amountCommitment crypto.PublicKeyBytes) {
	// k^o_t = H_n("..t..", s^ctx_sr, C_a)
	ScalarTranscript(
		extensionOut, hasher, secretSenderReceiver[:],
		[]byte(DomainSeparatorOneTimeExtensionT), amountCommitment[:],
	)
}
