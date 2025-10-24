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

	torsionChecked bool
}

// UnsafeForceTorsionChecked Force torsion checks to pass and be skipped. Useful if Destination has been verified previously
func (p *PaymentProposalV1) UnsafeForceTorsionChecked() {
	p.torsionChecked = true
}

// ECDHParts get_normal_proposal_ecdh_parts
func (p *PaymentProposalV1) ECDHParts(hasher *blake2b.Digest, inputContext []byte) (ephemeralPubkey, senderReceiverUnctx crypto.X25519PublicKey) {
	if !p.torsionChecked {
		if !p.Destination.Address.Valid() {
			// failed decoding or torsion checks
			return crypto.ZeroX25519PublicKey, crypto.ZeroX25519PublicKey
		}
		p.torsionChecked = true
	}

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
var ErrTwistedReceiver = errors.New("receiver public key is twisted or invalid")

// OutputPartial Calculates cacheable partial values
func (p *PaymentProposalV1) OutputPartial(hasher *blake2b.Digest, inputContext []byte, isCoinbase bool) (ephemeralPubkey, senderReceiverUnctx crypto.X25519PublicKey, secretSenderReceiver types.Hash, err error) {
	if err = p.Check(isCoinbase); err != nil {
		return crypto.ZeroX25519PublicKey, crypto.ZeroX25519PublicKey, types.ZeroHash, err
	}

	// 3. make D_e and do external ECDH
	ephemeralPubkey, senderReceiverUnctx = p.ECDHParts(hasher, inputContext[:])

	// err on twisted view/spend pub
	if ephemeralPubkey == crypto.ZeroX25519PublicKey || senderReceiverUnctx == crypto.ZeroX25519PublicKey {
		return crypto.ZeroX25519PublicKey, crypto.ZeroX25519PublicKey, types.ZeroHash, ErrTwistedReceiver
	}

	// 4. build the output enote address pieces
	secretSenderReceiver = makeSenderReceiverSecret(hasher, senderReceiverUnctx, ephemeralPubkey, inputContext[:])

	return ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, nil
}

func (p *PaymentProposalV1) Check(isCoinbase bool) error {
	if p.Randomness == [monero.JanusAnchorSize]byte{} {
		return ErrInvalidRandomness
	}
	if isCoinbase && p.Destination.Address.IsSubaddress() {
		// TODO :)
		return ErrUnsupportedCoinbaseSubaddress
	}
	if isCoinbase && p.Destination.PaymentId != [monero.PaymentIdSize]byte{} {
		// TODO :)
		return ErrUnsupportedCoinbasePaymentId
	}
	return nil
}

// CoinbaseOutputFromPartial Make a coinbase payment output from OutputPartial values
func (p *PaymentProposalV1) CoinbaseOutputFromPartial(hasher *blake2b.Digest, enote *CoinbaseEnoteV1, inputContext []byte, ephemeralPubkey, senderReceiverUnctx crypto.X25519PublicKey, secretSenderReceiver types.Hash) {
	enote.EphemeralPubKey = ephemeralPubkey

	// 4. build the output enote address pieces
	{

		// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
		{
			// 2. C_a = k_a G + a H
			amountCommitment := makeAmountCommitmentCoinbase(p.Amount)

			// 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
			enote.OneTimeAddress = makeOnetimeAddress(hasher, p.Destination.Address.SpendPublicKey().AsPoint(), secretSenderReceiver, amountCommitment)
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

// CoinbaseOutput Make a coinbase payment output
func (p *PaymentProposalV1) CoinbaseOutput(enote *CoinbaseEnoteV1, blockIndex uint64) (err error) {
	// 2. coinbase input context
	inputContext := MakeCoinbaseInputContext(blockIndex)

	var hasher blake2b.Digest

	ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, err := p.OutputPartial(&hasher, inputContext[:], true)
	if err != nil {
		return err
	}

	p.CoinbaseOutputFromPartial(&hasher, enote, inputContext[:], ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver)

	enote.BlockIndex = blockIndex

	return nil
}

// Output Make a normal payment output, non-change
func (p *PaymentProposalV1) Output(out *RCTEnoteProposal, firstKeyImage crypto.PublicKeyBytes) (err error) {

	// 2. input context
	inputContext := MakeInputContext(firstKeyImage)

	var hasher blake2b.Digest

	ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, err := p.OutputPartial(&hasher, inputContext[:], false)
	if err != nil {
		return err
	}

	out.Enote.FirstKeyImage = firstKeyImage
	out.Enote.EphemeralPubKey = ephemeralPubkey

	// 4. build the output enote address pieces
	{

		// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
		{

			// 1. k_a = H_n(s^ctx_sr, a, K^j_s, enote_type) if !coinbase, else 1
			var amountBlindingFactor crypto.PrivateKeyScalar
			makeAmountBlindingFactor(&hasher, &amountBlindingFactor, secretSenderReceiver, p.Amount, *p.Destination.Address.SpendPublicKey(), EnoteTypePayment)

			// 2. C_a = k_a G + a H
			out.Enote.AmountCommitment = makeAmountCommitment(p.Amount, &amountBlindingFactor)
			out.AmountBlindingFactor = amountBlindingFactor.AsBytes()

			// 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
			out.Enote.OneTimeAddress = makeOnetimeAddress(&hasher, p.Destination.Address.SpendPublicKey().AsPoint(), secretSenderReceiver, out.Enote.AmountCommitment)

			// 4. a_enc = a XOR m_a
			amountMask := makeAmountEncryptionMask(&hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
			var amountBuf [8]byte
			binary.LittleEndian.PutUint64(amountBuf[:], p.Amount)
			subtle.XORBytes(out.Enote.EncryptedAmount[:], amountBuf[:], amountMask[:])

			// 5. pid_enc = pid XOR m_pid
			pidMask := makePaymentIdEncryptionMask(&hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
			subtle.XORBytes(out.EncryptedPaymentId[:], p.Destination.PaymentId[:], pidMask[:])

		}

		// 3. vt = H_3(s_sr || input_context || Ko)
		out.Enote.ViewTag = makeViewTag(&hasher, senderReceiverUnctx, inputContext[:], out.Enote.OneTimeAddress)
	}
	// 5. anchor_enc = anchor XOR m_anchor
	{
		mask := makeAnchorEncryptionMask(&hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		subtle.XORBytes(out.Enote.EncryptedAnchor[:], p.Randomness[:], mask[:])
	}
	// 6. save the amount and block index
	out.Amount = p.Amount

	return nil
}

// MakeCoinbaseInputContext make_carrot_input_context_coinbase
func MakeCoinbaseInputContext(blockIndex uint64) (inputContext [1 + types.HashSize]byte) {
	inputContext[0] = DomainSeparatorInputContextCoinbase
	binary.LittleEndian.PutUint64(inputContext[1:], blockIndex)
	// left bytes are 0
	return inputContext
}

// MakeInputContext make_carrot_input_context
func MakeInputContext(firstRctKeyImage crypto.PublicKeyBytes) (inputContext [1 + types.HashSize]byte) {
	inputContext[0] = DomainSeparatorInputContextRingCT
	copy(inputContext[1:], firstRctKeyImage[:])
	return inputContext
}
