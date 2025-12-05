package carrot

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type PaymentProposalV1[T curve25519.PointOperations] struct {
	Destination DestinationV1 `json:"destination"`

	Amount uint64 `json:"amount"`
	// Randomness secret 16-byte randomness for Janus anchor
	Randomness [monero.JanusAnchorSize]byte `json:"randomness"`

	torsionChecked bool
}

// UnsafeForceTorsionChecked Force torsion checks to pass and be skipped. Useful if Destination has been verified previously
func (p *PaymentProposalV1[T]) UnsafeForceTorsionChecked() {
	p.torsionChecked = true
}

// ECDHParts get_normal_proposal_ecdh_parts
func (p *PaymentProposalV1[T]) ECDHParts(hasher *blake2b.Digest, inputContext []byte, isCoinbase bool) (ephemeralPubkey, senderReceiverUnctx curve25519.MontgomeryPoint) {
	var spendPub, viewPub curve25519.PublicKey[T]

	if _, err := spendPub.SetBytes(p.Destination.Address.SpendPublicKey()[:]); err != nil {
		// failed decoding or torsion checks
		return curve25519.ZeroMontgomeryPoint, curve25519.ZeroMontgomeryPoint
	}
	if _, err := viewPub.SetBytes(p.Destination.Address.ViewPublicKey()[:]); err != nil {
		// failed decoding or torsion checks
		return curve25519.ZeroMontgomeryPoint, curve25519.ZeroMontgomeryPoint
	}

	if !p.torsionChecked {
		if !viewPub.IsTorsionFree() || !spendPub.IsTorsionFree() {
			// failed decoding or torsion checks
			return curve25519.ZeroMontgomeryPoint, curve25519.ZeroMontgomeryPoint
		}

		p.torsionChecked = true
	}

	// 1. d_e = H_n(anchor_norm, input_context, K^j_s, pid))
	var ephemeralPrivateKey curve25519.Scalar
	makeEnoteEphemeralPrivateKey(hasher, &ephemeralPrivateKey, p.Randomness[:], inputContext, *p.Destination.Address.SpendPublicKey(), p.Destination.PaymentId)

	// 2. make D_e
	ephemeralPubkey = p.ephemeralPublicKey(&ephemeralPrivateKey, &spendPub)

	// 3. s_sr = d_e ConvertPointE(K^j_v)
	if isCoinbase {
		senderReceiverUnctx = makeUncontextualizedSharedKeySenderVarTime(&ephemeralPrivateKey, &viewPub)
	} else {
		senderReceiverUnctx = makeUncontextualizedSharedKeySender(&ephemeralPrivateKey, &viewPub)
	}

	return ephemeralPubkey, senderReceiverUnctx
}

func (p *PaymentProposalV1[T]) ephemeralPublicKey(key *curve25519.Scalar, spendPub *curve25519.PublicKey[T]) (out curve25519.MontgomeryPoint) {
	if p.Destination.Address.IsSubaddress() {
		// D_e = d_e ConvertPointE(K^j_s)
		return makeEnoteEphemeralPublicKeySubaddress(key, spendPub)
	} else {
		// D_e = d_e B
		return makeEnoteEphemeralPublicKeyCryptonote[T](key)
	}
}

var ErrUnsupportedCoinbaseSubaddress = errors.New("subaddresses aren't allowed as destinations of coinbase outputs")
var ErrUnsupportedCoinbasePaymentId = errors.New("integrated addresses aren't allowed as destinations of coinbase outputs")
var ErrInvalidRandomness = errors.New("invalid randomness for janus anchor (zero)")
var ErrTwistedReceiver = errors.New("receiver public key is twisted or invalid")

// OutputPartial Calculates cacheable partial values
func (p *PaymentProposalV1[T]) OutputPartial(hasher *blake2b.Digest, inputContext []byte, isCoinbase bool) (ephemeralPubkey, senderReceiverUnctx curve25519.MontgomeryPoint, secretSenderReceiver types.Hash, err error) {
	if err = p.Check(isCoinbase); err != nil {
		return curve25519.ZeroMontgomeryPoint, curve25519.ZeroMontgomeryPoint, types.ZeroHash, err
	}

	// 3. make D_e and do external ECDH
	ephemeralPubkey, senderReceiverUnctx = p.ECDHParts(hasher, inputContext[:], isCoinbase)

	// err on twisted view/spend pub
	if ephemeralPubkey == curve25519.ZeroMontgomeryPoint || senderReceiverUnctx == curve25519.ZeroMontgomeryPoint {
		return curve25519.ZeroMontgomeryPoint, curve25519.ZeroMontgomeryPoint, types.ZeroHash, ErrTwistedReceiver
	}

	// 4. build the output enote address pieces
	secretSenderReceiver = MakeSenderReceiverSecret(hasher, senderReceiverUnctx, ephemeralPubkey, inputContext[:])

	return ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, nil
}

func (p *PaymentProposalV1[T]) Check(isCoinbase bool) error {
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
func (p *PaymentProposalV1[T]) CoinbaseOutputFromPartial(hasher *blake2b.Digest, enote *CoinbaseEnoteV1, inputContext []byte, ephemeralPubkey, senderReceiverUnctx curve25519.MontgomeryPoint, secretSenderReceiver types.Hash) {
	enote.EphemeralPubKey = ephemeralPubkey

	var spendPub curve25519.PublicKey[T]
	if _, err := spendPub.SetBytes(p.Destination.Address.SpendPublicKey()[:]); err != nil {
		panic(err)
	}

	// 4. build the output enote address pieces
	{

		// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
		{
			// 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
			enote.OneTimeAddress = makeOneTimeAddressCoinbase(hasher, secretSenderReceiver, p.Amount, &spendPub)
		}

		// 3. vt = H_3(s_sr || input_context || Ko)
		enote.ViewTag = types.MakeFixed(makeViewTag(hasher, senderReceiverUnctx, inputContext, enote.OneTimeAddress))
	}
	// 5. anchor_enc = anchor XOR m_anchor
	{
		mask := makeAnchorEncryptionMask(hasher, secretSenderReceiver, enote.OneTimeAddress)
		subtle.XORBytes(enote.EncryptedAnchor.Slice(), p.Randomness[:], mask[:])
	}
	// 6. save the amount and block index
	enote.Amount = p.Amount
}

// CoinbaseOutput Make a coinbase payment output
func (p *PaymentProposalV1[T]) CoinbaseOutput(enote *CoinbaseEnoteV1, blockIndex uint64) (err error) {
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
func (p *PaymentProposalV1[T]) Output(out *RCTEnoteProposal, firstKeyImage curve25519.PublicKeyBytes) (err error) {

	// 2. input context
	inputContext := MakeInputContext(firstKeyImage)

	var hasher blake2b.Digest

	ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, err := p.OutputPartial(&hasher, inputContext[:], false)
	if err != nil {
		return err
	}

	var spendPub curve25519.PublicKey[T]
	if _, err = spendPub.SetBytes(p.Destination.Address.SpendPublicKey()[:]); err != nil {
		return err
	}

	out.Enote.FirstKeyImage = firstKeyImage
	out.Enote.EphemeralPubKey = ephemeralPubkey

	// 4. build the output enote address pieces
	{

		// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
		{

			// 1. k_a = H_n(s^ctx_sr, a, K^j_s, enote_type) if !coinbase, else 1
			var amountBlindingFactor curve25519.Scalar
			makeAmountBlindingFactor(&hasher, &amountBlindingFactor, secretSenderReceiver, p.Amount, *p.Destination.Address.SpendPublicKey(), EnoteTypePayment)

			// 2. C_a = k_a G + a H
			out.Enote.AmountCommitment = makeAmountCommitment[T](p.Amount, &amountBlindingFactor)
			out.AmountBlindingFactor = curve25519.PrivateKeyBytes(amountBlindingFactor.Bytes())

			// 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
			out.Enote.OneTimeAddress = makeOneTimeAddress(&hasher, secretSenderReceiver, &spendPub, out.Enote.AmountCommitment)

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
func MakeInputContext(firstRctKeyImage curve25519.PublicKeyBytes) (inputContext [1 + types.HashSize]byte) {
	inputContext[0] = DomainSeparatorInputContextRingCT
	copy(inputContext[1:], firstRctKeyImage[:])
	return inputContext
}
