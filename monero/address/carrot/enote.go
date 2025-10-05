package carrot

import (
	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
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
func makeEnoteEphemeralPrivateKey(anchor, inputContext []byte, spendPub crypto.PublicKey, paymentId [8]byte) *crypto.PrivateKeyScalar {
	// k_e = (H_64(anchor_norm, input_context, K^j_s, pid)) mod l
	transcript := FixedTranscript([]byte(DomainSeparatorEphemeralPrivateKey), anchor, inputContext, spendPub.AsSlice(), paymentId[:])

	return crypto.PrivateKeyFromScalar(crypto.ScalarDerive(nil, transcript))
}

// makeEnoteEphemeralPublicKeySubaddress make_carrot_enote_ephemeral_pubkey_subaddress
func makeEnoteEphemeralPublicKeySubaddress(key crypto.PrivateKey, spendKey crypto.PublicKey) (out crypto.X25519PublicKey) {
	// K_e = d_e K^j_s
	K_e := new(edwards25519.Point).UnsafeVarTimeScalarMult(key.AsScalar().Scalar(), spendKey.AsPoint().Point())

	// D_e = ConvertPointE(K_e)
	return crypto.ConvertPointE(K_e)
}

// makeEnoteEphemeralPublicKeyCryptonote make_carrot_enote_ephemeral_pubkey_cryptonote
func makeEnoteEphemeralPublicKeyCryptonote(key crypto.PrivateKey) (out crypto.X25519PublicKey) {
	// D_e = d_e B
	crypto.X25519ScalarBaseMult(&out, key.AsBytes())

	return out
}

// makeUncontextualizedSharedKeySender make_carrot_uncontextualized_shared_key_sender
func makeUncontextualizedSharedKeySender(ephemeralPrivKey crypto.PrivateKey, viewPub crypto.PublicKey) (senderReceiverUnctx crypto.X25519PublicKey) {
	//TODO: implement checks
	viewPubkeyX25519 := crypto.ConvertPointE(viewPub.AsPoint().Point())
	crypto.X25519ScalarMult(&senderReceiverUnctx, ephemeralPrivKey.AsBytes(), viewPubkeyX25519)
	return senderReceiverUnctx
}

// makeSenderReceiverSecret make_carrot_sender_receiver_secret
func makeSenderReceiverSecret(senderReceiverUnctx, ephemeralPubKey crypto.X25519PublicKey, inputContext []byte) types.Hash {
	// 1. s^ctx_sr = H_32(s_sr, D_e, input_context)
	transcript := FixedTranscript([]byte(DomainSeparatorSenderReceiverSecret), ephemeralPubKey[:], inputContext)
	return crypto.SecretDerive(senderReceiverUnctx[:], transcript)
}

// makeOnetimeAddress make_carrot_onetime_address
func makeOnetimeAddress(spendPub crypto.PublicKeyBytes, secretSenderReceiver types.Hash, amountCommitment crypto.PublicKey) crypto.PublicKeyBytes {
	var sender_extension_pubkey crypto.PublicKey
	// K^o_ext = k^o_g G + k^o_t T
	// make_carrot_onetime_address_extension_pubkey
	{
		var sender_extension_G, sender_extension_T *edwards25519.Scalar
		// k^o_g = H_n("..g..", s^ctx_sr, C_a)
		// make_carrot_onetime_address_extension_g
		{
			// k^o_g = H_n("..g..", s^ctx_sr, C_a)
			transcript := FixedTranscript([]byte(DomainSeparatorOneTimeExtensionG), amountCommitment.AsSlice())
			sender_extension_G = crypto.ScalarDerive(secretSenderReceiver[:], transcript)
		}

		// k^o_t = H_n("..t..", s^ctx_sr, C_a)
		// make_carrot_onetime_address_extension_t
		{
			// k^o_t = H_n("..t..", s^ctx_sr, C_a)
			transcript := FixedTranscript([]byte(DomainSeparatorOneTimeExtensionT), amountCommitment.AsSlice())
			sender_extension_T = crypto.ScalarDerive(secretSenderReceiver[:], transcript)
		}

		// K^o_ext = k^o_g G + k^o_t T
		sender_extension_pubkey = crypto.RctAddKeys2(crypto.PrivateKeyFromScalar(sender_extension_G), crypto.PrivateKeyFromScalar(sender_extension_T), crypto.PublicKeyFromPoint(crypto.GeneratorT))
	}

	// Ko = K^j_s + K^o_ext
	return spendPub.AsPoint().Add(sender_extension_pubkey.AsPoint()).AsBytes()
}

// makeViewTag make_carrot_view_tag
func makeViewTag(senderReceiverUnctx crypto.X25519PublicKey, inputContext []byte, oneTimeAddress crypto.PublicKeyBytes) [monero.CarrotViewTagSize]byte {
	// vt = H_3(s_sr || input_context || Ko)

	transcript := FixedTranscript([]byte(DomainSeparatorViewTag), inputContext, oneTimeAddress[:])
	return [monero.CarrotViewTagSize]byte(crypto.SecretDeriveN(monero.CarrotViewTagSize, senderReceiverUnctx[:], transcript))
}

// makeAnchorEncryptionMask make_carrot_anchor_encryption_mask
func makeAnchorEncryptionMask(secretSenderReceiver types.Hash, oneTimeAddress crypto.PublicKeyBytes) [monero.JanusAnchorSize]byte {
	// m_anchor = H_16(s^ctx_sr, Ko)
	transcript := FixedTranscript([]byte(DomainSeparatorEncryptionMaskAnchor), oneTimeAddress[:])
	return [monero.JanusAnchorSize]byte(crypto.SecretDeriveN(monero.JanusAnchorSize, secretSenderReceiver[:], transcript))
}
