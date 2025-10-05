package carrot

import (
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

const (
	EnoteTypePAYMENT = uint8(0)
	EnoteTypeCHANGE  = uint8(1)
)

// makeEnoteEphemeralPrivateKey make_carrot_enote_ephemeral_privkey
func makeEnoteEphemeralPrivateKey(ephemeralPrivateKey *crypto.PrivateKeyScalar, anchor, inputContext []byte, spendPub crypto.PublicKeyBytes, paymentId [8]byte) {
	// k_e = (H_64(anchor_norm, input_context, K^j_s, pid)) mod l
	ScalarTranscript(
		ephemeralPrivateKey.Scalar(), nil,
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
func makeEnoteEphemeralPublicKeyCryptonote(key crypto.PrivateKeyBytes) (out crypto.X25519PublicKey) {
	// D_e = d_e B
	crypto.X25519ScalarBaseMult(&out, key)

	return out
}

// makeUncontextualizedSharedKeySender make_carrot_uncontextualized_shared_key_sender
func makeUncontextualizedSharedKeySender(ephemeralPrivKey crypto.PrivateKeyBytes, viewPub *crypto.PublicKeyPoint) (senderReceiverUnctx crypto.X25519PublicKey) {
	//TODO: implement checks
	viewPubkeyX25519 := crypto.ConvertPointE(viewPub.Point())
	crypto.X25519ScalarMult(&senderReceiverUnctx, ephemeralPrivKey, viewPubkeyX25519)
	return senderReceiverUnctx
}

// makeSenderReceiverSecret make_carrot_sender_receiver_secret
func makeSenderReceiverSecret(senderReceiverUnctx, ephemeralPubKey crypto.X25519PublicKey, inputContext []byte) (out types.Hash) {
	// 1. s^ctx_sr = H_32(s_sr, D_e, input_context)
	HashedTranscript(
		out[:], senderReceiverUnctx[:],
		[]byte(DomainSeparatorSenderReceiverSecret), ephemeralPubKey[:], inputContext,
	)
	return out
}

// makeOnetimeAddress make_carrot_onetime_address
func makeOnetimeAddress(spendPub *crypto.PublicKeyPoint, secretSenderReceiver types.Hash, amountCommitment crypto.PublicKeyBytes) crypto.PublicKeyBytes {
	var senderExtensionPubkey crypto.PublicKeyPoint
	// K^o_ext = k^o_g G + k^o_t T
	// make_carrot_onetime_address_extension_pubkey
	{
		var senderExtensionG, senderExtensionT edwards25519.Scalar
		// k^o_g = H_n("..g..", s^ctx_sr, C_a)
		// make_carrot_onetime_address_extension_g
		ScalarTranscript(
			&senderExtensionG, secretSenderReceiver[:],
			[]byte(DomainSeparatorOneTimeExtensionG), amountCommitment[:],
		)

		// k^o_t = H_n("..t..", s^ctx_sr, C_a)
		// make_carrot_onetime_address_extension_t
		ScalarTranscript(
			&senderExtensionT, secretSenderReceiver[:],
			[]byte(DomainSeparatorOneTimeExtensionT), amountCommitment[:],
		)

		// K^o_ext = k^o_g G + k^o_t T
		senderExtensionPubkey.Point().VarTimeDoubleScalarBaseMult(&senderExtensionT, crypto.GeneratorT, &senderExtensionG)
	}

	// Ko = K^j_s + K^o_ext
	return spendPub.Add(&senderExtensionPubkey).AsBytes()
}

// makeViewTag make_carrot_view_tag
func makeViewTag(senderReceiverUnctx crypto.X25519PublicKey, inputContext []byte, oneTimeAddress crypto.PublicKeyBytes) (out [monero.CarrotViewTagSize]byte) {
	// vt = H_3(s_sr || input_context || Ko)

	HashedTranscript(
		out[:], senderReceiverUnctx[:],
		[]byte(DomainSeparatorViewTag), inputContext, oneTimeAddress[:],
	)
	return out
}

// makeAnchorEncryptionMask make_carrot_anchor_encryption_mask
func makeAnchorEncryptionMask(secretSenderReceiver types.Hash, oneTimeAddress crypto.PublicKeyBytes) (out [monero.JanusAnchorSize]byte) {
	// m_anchor = H_16(s^ctx_sr, Ko)
	HashedTranscript(
		out[:], secretSenderReceiver[:],
		[]byte(DomainSeparatorEncryptionMaskAnchor), oneTimeAddress[:],
	)
	return out
}
