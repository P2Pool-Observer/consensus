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

func (p *PaymentProposalV1) CoinbaseOutput(enote *CoinbaseEnoteV1, blockIndex uint64) error {
	if p.Randomness == [monero.JanusAnchorSize]byte{} {
		return errors.New("invalid randomness for janus anchor (zero)")
	}
	if p.Destination.Address.IsSubaddress() {
		// TODO :)
		return errors.New("subaddresses aren't allowed as destinations of coinbase outputs")
	}
	if p.Destination.PaymentId != [8]byte{} {
		// TODO :)
		return errors.New("integrated addresses aren't allowed as destinations of coinbase outputs")
	}
	var hasher blake2b.Digest

	// 2. coinbase input context
	// make_carrot_input_context_coinbase
	var inputContext [1 + types.HashSize]byte
	inputContext[0] = DomainSeparatorInputContextCoinbase
	binary.LittleEndian.PutUint64(inputContext[1:], blockIndex)
	// left bytes are 0

	var senderReceiverUnctx crypto.X25519PublicKey
	// 3. make D_e and do external ECDH
	enote.EphemeralPubKey, senderReceiverUnctx = p.ECDHParts(&hasher, inputContext[:])

	var secretSenderReceiver types.Hash
	// 4. build the output enote address pieces
	{
		secretSenderReceiver = makeSenderReceiverSecret(&hasher, senderReceiverUnctx, enote.EphemeralPubKey, inputContext[:])

		// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc

		{
			var amountBlindingFactorOut crypto.PrivateKeyBytes
			if true { // coinbase amount commitment
				// 1. k_a = H_n(s^ctx_sr, a, K^j_s, enote_type) if !coinbase, else 1
				amountBlindingFactorOut[0] = 1
			}

			// 2. C_a = k_a G + a H
			var amountCommitmentOut crypto.PublicKeyPoint
			crypto.RctCommit(&amountCommitmentOut, p.Amount, amountBlindingFactorOut.AsScalar())

			// 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
			enote.OneTimeAddress = makeOnetimeAddress(&hasher, p.Destination.Address.SpendPublicKey().AsPoint(), secretSenderReceiver, amountCommitmentOut.AsBytes())

			/*
				// 4. a_enc = a XOR m_a
				{
					var mask [8]byte
					// m_a = H_8(s^ctx_sr, Ko)
					{
						transcript := FixedTranscript([]byte(DomainSeparatorEncryptionMaskAmount), enote.OneTimeAddress[:])
						h := crypto.SecretDerive(transcript)
						mask = [8]byte(h[:8])
					}
					enote.Amount
				}
			*/
		}

		// 3. vt = H_3(s_sr || input_context || Ko)
		enote.ViewTag = makeViewTag(&hasher, senderReceiverUnctx, inputContext[:], enote.OneTimeAddress)
	}
	// 5. anchor_enc = anchor XOR m_anchor
	{
		mask := makeAnchorEncryptionMask(&hasher, secretSenderReceiver, enote.OneTimeAddress)
		subtle.XORBytes(enote.EncryptedAnchor[:], p.Randomness[:], mask[:])
	}
	// 6. save the amount and block index
	enote.Amount = p.Amount
	enote.BlockIndex = blockIndex

	return nil
}
