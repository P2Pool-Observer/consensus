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
		if !viewPub.IsTorsionFree() || !spendPub.IsTorsionFree() || spendPub.IsSmallOrder() || viewPub.IsSmallOrder() {
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
		senderReceiverUnctx = MakeUncontextualizedSharedKeySenderVarTime(&ephemeralPrivateKey, &viewPub)
	} else {
		senderReceiverUnctx = MakeUncontextualizedSharedKeySender(&ephemeralPrivateKey, &viewPub)
	}

	return ephemeralPubkey, senderReceiverUnctx
}

func (p *PaymentProposalV1[T]) ephemeralPublicKey(key *curve25519.Scalar, spendPub *curve25519.PublicKey[T]) (out curve25519.MontgomeryPoint) {
	if p.Destination.Address.IsSubaddress() {
		// D_e = d_e ConvertPointE(K^j_s)
		return MakeEnoteEphemeralPublicKeySubaddress(key, spendPub)
	} else {
		// D_e = d_e B
		return MakeEnoteEphemeralPublicKeyCryptonote[T](key)
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
	ephemeralPubkey, senderReceiverUnctx = p.ECDHParts(hasher, inputContext, isCoinbase)

	// err on twisted view/spend pub
	if ephemeralPubkey == curve25519.ZeroMontgomeryPoint || senderReceiverUnctx == curve25519.ZeroMontgomeryPoint {
		return curve25519.ZeroMontgomeryPoint, curve25519.ZeroMontgomeryPoint, types.ZeroHash, ErrTwistedReceiver
	}

	// 4. build the output enote address pieces
	secretSenderReceiver = MakeSenderReceiverSecret(hasher, senderReceiverUnctx, ephemeralPubkey, inputContext)

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
	// 6. save the amount
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

func (p *PaymentProposalV1[T]) CoinbaseEphemeralPrivateKey(blockIndex uint64) curve25519.Scalar {
	inputContext := MakeCoinbaseInputContext(blockIndex)
	var ephemeralPrivateKey curve25519.Scalar
	makeEnoteEphemeralPrivateKey(&blake2b.Digest{}, &ephemeralPrivateKey, p.Randomness[:], inputContext[:], *p.Destination.Address.SpendPublicKey(), p.Destination.PaymentId)
	return ephemeralPrivateKey
}

func (p *PaymentProposalV1[T]) EphemeralPrivateKey(firstKeyImage curve25519.PublicKeyBytes) curve25519.Scalar {
	inputContext := MakeInputContext(firstKeyImage)
	var ephemeralPrivateKey curve25519.Scalar
	makeEnoteEphemeralPrivateKey(&blake2b.Digest{}, &ephemeralPrivateKey, p.Randomness[:], inputContext[:], *p.Destination.Address.SpendPublicKey(), p.Destination.PaymentId)
	return ephemeralPrivateKey
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

	out.Enote.FirstKeyImage = firstKeyImage
	out.Enote.EphemeralPubKey = ephemeralPubkey

	// 4. build the output enote address pieces
	if err = getExternalOutputProposalParts[T](out, &hasher, senderReceiverUnctx, secretSenderReceiver, *p.Destination.Address.SpendPublicKey(), p.Destination.PaymentId, p.Amount, EnoteTypePayment, inputContext[:]); err != nil {
		return err
	}

	// 5. anchor_enc = anchor XOR m_anchor
	{
		mask := makeAnchorEncryptionMask(&hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		subtle.XORBytes(out.Enote.EncryptedAnchor[:], p.Randomness[:], mask[:])
	}
	// 6. save the amount
	out.Amount = p.Amount

	return nil
}

// getExternalOutputProposalParts get_external_output_proposal_parts
func getExternalOutputProposalParts[T curve25519.PointOperations](out *RCTEnoteProposal, hasher *blake2b.Digest, senderReceiverUnctx curve25519.MontgomeryPoint, secretSenderReceiver types.Hash, destinationSpendPub curve25519.PublicKeyBytes, paymentId [monero.PaymentIdSize]byte, amount uint64, enoteType EnoteType, inputContext []byte) (err error) {

	var spendPub curve25519.PublicKey[T]
	if _, err = spendPub.SetBytes(destinationSpendPub[:]); err != nil {
		return err
	}

	// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
	{

		// 1. k_a = H_n(s^ctx_sr, a, K^j_s, enote_type) if !coinbase, else 1
		var amountBlindingFactor curve25519.Scalar
		makeAmountBlindingFactor(hasher, &amountBlindingFactor, secretSenderReceiver, amount, destinationSpendPub, enoteType)

		// 2. C_a = k_a G + a H
		out.Enote.AmountCommitment = makeAmountCommitment[T](amount, &amountBlindingFactor)
		out.AmountBlindingFactor = curve25519.PrivateKeyBytes(amountBlindingFactor.Bytes())

		// 3. Ko = K^j_s + K^o_ext = K^j_s + (k^o_g G + k^o_t T)
		out.Enote.OneTimeAddress = makeOneTimeAddress(hasher, secretSenderReceiver, &spendPub, out.Enote.AmountCommitment)

		// 4. a_enc = a XOR m_a
		amountMask := makeAmountEncryptionMask(hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		var amountBuf [8]byte
		binary.LittleEndian.PutUint64(amountBuf[:], amount)
		subtle.XORBytes(out.Enote.EncryptedAmount[:], amountBuf[:], amountMask[:])

		// 5. pid_enc = pid XOR m_pid
		pidMask := makePaymentIdEncryptionMask(hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		subtle.XORBytes(out.EncryptedPaymentId[:], paymentId[:], pidMask[:])

	}

	// 3. vt = H_3(s_sr || input_context || Ko)
	out.Enote.ViewTag = makeViewTag(hasher, senderReceiverUnctx, inputContext, out.Enote.OneTimeAddress)

	return nil
}

// getOutputProposalParts get_output_proposal_parts
func getOutputProposalParts[T curve25519.PointOperations](out *RCTEnoteProposal, hasher *blake2b.Digest, secretSenderReceiver types.Hash, destinationSpendPub curve25519.PublicKeyBytes, paymentId [monero.PaymentIdSize]byte, amount uint64, enoteType EnoteType, coinbaseAmountCommitment bool) (err error) {

	var spendPub curve25519.PublicKey[T]
	if _, err = spendPub.SetBytes(destinationSpendPub[:]); err != nil {
		return err
	}

	// 2. get other parts: k_a, C_a, Ko, a_enc, pid_enc
	{

		// 1. k_a = H_n(s^ctx_sr, a, K^j_s, enote_type) if !coinbase, else 1
		var amountBlindingFactor curve25519.Scalar
		makeAmountBlindingFactor(hasher, &amountBlindingFactor, secretSenderReceiver, amount, destinationSpendPub, enoteType)

		// 2. C_a = k_a G + a H
		out.Enote.AmountCommitment = makeAmountCommitment[T](amount, &amountBlindingFactor)
		out.AmountBlindingFactor = curve25519.PrivateKeyBytes(amountBlindingFactor.Bytes())

		// 3. K^o_ext = k^g_o G + k^t_o T, where:
		// 4. K_o = K^j_s + K^o_ext
		if coinbaseAmountCommitment {
			out.Enote.OneTimeAddress = makeOneTimeAddressCoinbase(hasher, secretSenderReceiver, amount, &spendPub)
		} else {
			out.Enote.OneTimeAddress = makeOneTimeAddress(hasher, secretSenderReceiver, &spendPub, out.Enote.AmountCommitment)
		}

		// 4. a_enc = a XOR m_a
		amountMask := makeAmountEncryptionMask(hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		var amountBuf [8]byte
		binary.LittleEndian.PutUint64(amountBuf[:], amount)
		subtle.XORBytes(out.Enote.EncryptedAmount[:], amountBuf[:], amountMask[:])

		// 5. pid_enc = pid XOR m_pid
		pidMask := makePaymentIdEncryptionMask(hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		subtle.XORBytes(out.EncryptedPaymentId[:], paymentId[:], pidMask[:])

	}

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

type PaymentProposalSelfSendV1[T curve25519.PointOperations] struct {
	DestinationSpendPub curve25519.PublicKeyBytes `json:"destination_spend_pubkey"`

	Amount uint64 `json:"amount"`

	EnoteType EnoteType `json:"enote_type"`

	EnoteEphemeralPub *curve25519.MontgomeryPoint `json:"enote_ephemeral_pubkey,omitempty"`

	// InternalMessage anchor: arbitrary, pre-encrypted message for _internal_ selfsends
	InternalMessage *[monero.JanusAnchorSize]byte `json:"internal_message,omitempty"`
}

func (p *PaymentProposalSelfSendV1[T]) SpecialOutput(out *RCTEnoteProposal, firstKeyImage curve25519.PublicKeyBytes, viewIncomingSecret curve25519.PrivateKeyBytes, otherEphemeralPub *curve25519.MontgomeryPoint) (err error) {
	if p.InternalMessage != nil {
		return errors.New("invalid internal message")
	}

	// 2. input context: input_context = "R" || KI_1
	inputContext := MakeInputContext(firstKeyImage)

	// 3. D_e
	ephemeralPubkey, err := p.tryResolveSelfSendEphemeralPub(otherEphemeralPub)
	if err != nil {
		return err
	}

	// 4. s_sr = k_v D_e
	var senderReceiverUnctx curve25519.MontgomeryPoint
	curve25519.MontgomeryUnclampedScalarMult(&senderReceiverUnctx, viewIncomingSecret, ephemeralPubkey)

	var hasher blake2b.Digest

	secretSenderReceiver := MakeSenderReceiverSecret(&hasher, senderReceiverUnctx, ephemeralPubkey, inputContext[:])

	out.Enote.FirstKeyImage = firstKeyImage
	out.Enote.EphemeralPubKey = ephemeralPubkey

	// 5. build the output enote address pieces
	if err = getExternalOutputProposalParts[T](out, &hasher, senderReceiverUnctx, secretSenderReceiver, p.DestinationSpendPub, [monero.PaymentIdSize]byte{}, p.Amount, p.EnoteType, inputContext[:]); err != nil {
		return err
	}

	// 6. make special janus anchor: anchor_sp = H_16(D_e, input_context, Ko, k_v)
	specialAnchor := makeJanusAnchorSpecial(&hasher, ephemeralPubkey, inputContext[:], out.Enote.OneTimeAddress, viewIncomingSecret)

	// 7. encrypt special anchor: anchor_enc = anchor XOR m_anchor
	{
		mask := makeAnchorEncryptionMask(&hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		subtle.XORBytes(out.Enote.EncryptedAnchor[:], specialAnchor[:], mask[:])
	}

	// 8. save the  amount
	out.Amount = p.Amount

	return nil
}

func (p *PaymentProposalSelfSendV1[T]) InternalOutput(out *RCTEnoteProposal, firstKeyImage curve25519.PublicKeyBytes, viewBalanceSecret types.Hash, otherEphemeralPub *curve25519.MontgomeryPoint) (err error) {

	// 2. input context: input_context = "R" || KI_1
	inputContext := MakeInputContext(firstKeyImage)

	// 3. D_e
	ephemeralPubkey, err := p.tryResolveSelfSendEphemeralPub(otherEphemeralPub)
	if err != nil {
		return err
	}

	var hasher blake2b.Digest

	// 4. s^ctx_sr = H_32(s_vb, D_e, input_context)
	secretSenderReceiver := MakeSenderReceiverSecret(&hasher, viewBalanceSecret, ephemeralPubkey, inputContext[:])

	out.Enote.FirstKeyImage = firstKeyImage
	out.Enote.EphemeralPubKey = ephemeralPubkey

	// 5. build the output enote address pieces
	if err = getOutputProposalParts[T](out, &hasher, secretSenderReceiver, p.DestinationSpendPub, [monero.PaymentIdSize]byte{}, p.Amount, p.EnoteType, false); err != nil {
		return err
	}

	// 6. vt = H_3(s_vb || input_context || Ko)
	out.Enote.ViewTag = makeViewTag(&hasher, viewBalanceSecret, inputContext[:], out.Enote.OneTimeAddress)

	// 7. anchor = given message OR 0s, if not available
	var anchor [monero.JanusAnchorSize]byte
	if p.InternalMessage != nil {
		anchor = *p.InternalMessage
	}

	// 8. encrypt anchor: anchor_enc = anchor XOR m_anchor
	{
		mask := makeAnchorEncryptionMask(&hasher, secretSenderReceiver, out.Enote.OneTimeAddress)
		subtle.XORBytes(out.Enote.EncryptedAnchor[:], anchor[:], mask[:])
	}

	// 8. save the  amount
	out.Amount = p.Amount

	return nil
}

func (p *PaymentProposalSelfSendV1[T]) tryResolveSelfSendEphemeralPub(otherEphemeralPub *curve25519.MontgomeryPoint) (pub curve25519.MontgomeryPoint, err error) {
	if p.EnoteEphemeralPub != nil {
		if otherEphemeralPub != nil {
			if *p.EnoteEphemeralPub == *otherEphemeralPub {
				return *p.EnoteEphemeralPub, nil
			} else {
				return curve25519.ZeroMontgomeryPoint, errors.New("mismatched enote ephemeral pubkey")
			}
		}
		return *p.EnoteEphemeralPub, nil
	} else if otherEphemeralPub != nil {
		return *otherEphemeralPub, nil
	} else {
		return curve25519.ZeroMontgomeryPoint, errors.New("missing enote ephemeral pubkey")
	}
}

//TODO: internal output
