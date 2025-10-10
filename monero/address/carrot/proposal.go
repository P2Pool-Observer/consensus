package carrot

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type PaymentProposalV1 struct {
	Destination DestinationV1 `json:"destination"`

	Amount uint64 `json:"amount"`
	// Randomness secret 16-byte randomness for Janus anchor
	Randomness [monero.JanusAnchorSize]byte `json:"randomness"`
}

// ECDHParts get_normal_proposal_ecdh_parts
func (p *PaymentProposalV1) ECDHParts(hasher *blake2b.Digest, inputContext []byte) (ephemeralPubkey, senderReceiverUnctx crypto.X25519PublicKey) {
	// 1. d_e = H_n(anchor_norm, input_context, K^j_s, pid))
	var ephemeralPrivateKey crypto.PrivateKeyScalar
	makeEnoteEphemeralPrivateKey(hasher, &ephemeralPrivateKey, p.Randomness[:], inputContext, *p.Destination.Address.SpendPublicKey(), p.Destination.PaymentId)

	// 2. make D_e
	ephemeralPubkey = p.ephemeralPublicKey(&ephemeralPrivateKey)

	// 3. s_sr = d_e ConvertPointE(K^j_v)
	senderReceiverUnctx = makeUncontextualizedSharedKeySender(ephemeralPrivateKey.AsBytes(), p.Destination.Address.ViewPublicKey().AsPoint())

	return ephemeralPubkey, senderReceiverUnctx
}

func (p *PaymentProposalV1) ephemeralPublicKey(key *crypto.PrivateKeyScalar) (out crypto.X25519PublicKey) {
	if p.Destination.Address.IsSubaddress() {
		// D_e = d_e ConvertPointE(K^j_s)
		return makeEnoteEphemeralPublicKeySubaddress(key, p.Destination.Address.SpendPublicKey().AsPoint())
	} else {
		// D_e = d_e B
		return makeEnoteEphemeralPublicKeyCryptonote(key)
	}
}

var ErrUnsupportedCoinbaseSubaddress = errors.New("subaddresses aren't allowed as destinations of coinbase outputs")
var ErrUnsupportedCoinbasePaymentId = errors.New("integrated addresses aren't allowed as destinations of coinbase outputs")
var ErrInvalidRandomness = errors.New("invalid randomness for janus anchor (zero)")
var ErrTwistedReceiver = errors.New("receiver view public key is twisted")

// CoinbaseOutputPartial Calculates cacheable partial values
func (p *PaymentProposalV1) CoinbaseOutputPartial(hasher *blake2b.Digest, inputContext []byte) (ephemeralPubkey, senderReceiverUnctx crypto.X25519PublicKey, secretSenderReceiver types.Hash, err error) {
	if p.Randomness == [monero.JanusAnchorSize]byte{} {
		return crypto.ZeroX25519PublicKey, crypto.ZeroX25519PublicKey, types.ZeroHash, ErrInvalidRandomness
	}
	if p.Destination.Address.IsSubaddress() {
		// TODO :)
		return crypto.ZeroX25519PublicKey, crypto.ZeroX25519PublicKey, types.ZeroHash, ErrUnsupportedCoinbaseSubaddress
	}
	if p.Destination.PaymentId != [monero.PaymentIdSize]byte{} {
		// TODO :)
		return crypto.ZeroX25519PublicKey, crypto.ZeroX25519PublicKey, types.ZeroHash, ErrUnsupportedCoinbasePaymentId
	}

	// 3. make D_e and do external ECDH
	ephemeralPubkey, senderReceiverUnctx = p.ECDHParts(hasher, inputContext[:])

	// err on twist
	if senderReceiverUnctx == crypto.ZeroX25519PublicKey {
		return crypto.ZeroX25519PublicKey, crypto.ZeroX25519PublicKey, types.ZeroHash, ErrTwistedReceiver
	}

	// 4. build the output enote address pieces
	secretSenderReceiver = makeSenderReceiverSecret(hasher, senderReceiverUnctx, ephemeralPubkey, inputContext[:])

	return ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, nil
}

func (p *PaymentProposalV1) CoinbaseOutputFromPartial(hasher *blake2b.Digest, enote *CoinbaseEnoteV1, inputContext []byte, ephemeralPubkey, senderReceiverUnctx crypto.X25519PublicKey, secretSenderReceiver types.Hash) {
	enote.EphemeralPubKey = ephemeralPubkey

	// 4. build the output enote address pieces
	{

		// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
		{
			// 2. C_a = k_a G + a H
			amountCommitmentOut := makeAmountCommitmentCoinbase(p.Amount)

			// 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
			enote.OneTimeAddress = makeOnetimeAddress(hasher, p.Destination.Address.SpendPublicKey().AsPoint(), secretSenderReceiver, amountCommitmentOut)
		}

		// 3. vt = H_3(s_sr || input_context || Ko)
		enote.ViewTag = makeViewTag(hasher, senderReceiverUnctx, inputContext, enote.OneTimeAddress)
	}
	// 5. anchor_enc = anchor XOR m_anchor
	{
		mask := makeAnchorEncryptionMask(hasher, secretSenderReceiver, enote.OneTimeAddress)
		subtle.XORBytes(enote.EncryptedAnchor[:], p.Randomness[:], mask[:])
	}
	// 6. save the amount and block index
	enote.Amount = p.Amount
}

func (p *PaymentProposalV1) CoinbaseOutput(enote *CoinbaseEnoteV1, blockIndex uint64) (err error) {
	// 2. coinbase input context
	inputContext := MakeCarrotCoinbaseInputContext(blockIndex)

	var hasher blake2b.Digest

	ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, err := p.CoinbaseOutputPartial(&hasher, inputContext[:])
	if err != nil {
		return err
	}

	p.CoinbaseOutputFromPartial(&hasher, enote, inputContext[:], ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver)

	enote.BlockIndex = blockIndex

	return nil
}

// MakeCarrotCoinbaseInputContext make_carrot_input_context_coinbase
func MakeCarrotCoinbaseInputContext(blockIndex uint64) (inputContext [1 + types.HashSize]byte) {
	inputContext[0] = DomainSeparatorInputContextCoinbase
	binary.LittleEndian.PutUint64(inputContext[1:], blockIndex)
	// left bytes are 0
	return inputContext
}
