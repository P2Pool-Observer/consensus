package fcmp_plus_plus

import (
	"errors"
	"io"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// Proof FCMP++ SAL and membership proof
type Proof[T curve25519.PointOperations] struct {
	Inputs []InputTuple[T]
	FCMP   MembershipProof
}

type InputTuple[T curve25519.PointOperations] struct {
	Input Input[T]
	SAL   SpendAuthAndLinkability[T]
}

type Input[T curve25519.PointOperations] struct {
	// OTilde O~ from the input commitment.
	OTilde curve25519.PublicKey[T]
	// ITilde I~ from the input commitment.
	ITilde curve25519.PublicKey[T]
	// R from the input commitment.
	R curve25519.PublicKey[T]
	// CTilde C~ from the input commitment (the pseudo-out).
	CTilde curve25519.PublicKey[T]
}

func (i *Input[T]) Transcript(transcript *blake2b.Digest, L *curve25519.PublicKey[T]) {
	_, _ = transcript.Write(i.OTilde.Bytes())
	_, _ = transcript.Write(i.ITilde.Bytes())
	_, _ = transcript.Write(i.CTilde.Bytes())
	_, _ = transcript.Write(i.R.Bytes())
	_, _ = transcript.Write(L.Bytes())
}

func (i *Input[T]) FromReader(reader utils.ReaderAndByteReader, pseudoOut *curve25519.PublicKey[T]) (err error) {
	if err = i.OTilde.FromReader(reader); err != nil {
		return err
	}
	if err = i.ITilde.FromReader(reader); err != nil {
		return err
	}
	if err = i.R.FromReader(reader); err != nil {
		return err
	}
	i.CTilde = *pseudoOut
	return nil
}

func (p *Proof[T]) FromReader(reader utils.ReaderAndByteReader, pseudoOuts []curve25519.PublicKey[T], layers int) (err error) {
	p.Inputs = make([]InputTuple[T], 0, len(pseudoOuts))
	for _, o := range pseudoOuts {
		var i InputTuple[T]
		if err = i.Input.FromReader(reader, &o); err != nil {
			return err
		}
		if err = i.SAL.FromReader(reader); err != nil {
			return err
		}
		p.Inputs = append(p.Inputs, i)
	}

	if err = p.FCMP.FromReader(reader, len(pseudoOuts), layers); err != nil {
		return err
	}
	return nil
}

func (p *Proof[T]) Verify(verifier *BatchVerifier[T], signableTxHash types.Hash, tree any, layers int, keyImages []curve25519.PublicKey[T], randomReader io.Reader) (err error) {
	if len(keyImages) != len(p.Inputs) {
		return errors.New("invalid number of key images")
	}

	for i, ki := range keyImages {
		p.Inputs[i].SAL.Verify(verifier, signableTxHash, &p.Inputs[i].Input, &ki, randomReader)
	}

	//TODO: tree
	return nil
}

type MembershipProof struct {
	Proof        []byte
	RootBlindPOK [64]byte
}

func (p *MembershipProof) FromReader(reader utils.ReaderAndByteReader, inputs, layers int) (err error) {
	p.Proof = make([]byte, MembershipProofSize(inputs, layers)-64)
	if _, err = utils.ReadFullNoEscape(reader, p.Proof); err != nil {
		return err
	}
	if _, err = utils.ReadFullNoEscape(reader, p.RootBlindPOK[:]); err != nil {
		return err
	}
	return nil
}

const FCMP_PP_SAL_PROOF_SIZE_V1 = 12 * 32
const FCMP_PP_INPUT_TUPLE_SIZE_V1 = 3 * 32

func ProofSize(inputs, layers int) int {
	return MembershipProofSize(inputs, layers) + (inputs * (FCMP_PP_INPUT_TUPLE_SIZE_V1 + FCMP_PP_SAL_PROOF_SIZE_V1))
}

const COMMITMENT_WORD_LEN = 128

func MembershipProofSize(inputs, layers int) int {
	// AI, AO, AS, tau_x, u, t_caret, a, b for each BP
	proofElements := 16

	c1PaddedPow2, c2PaddedPow2 := IPARows(inputs, layers)
	{
		base := c1PaddedPow2
		res := 1
		for res < base {
			res <<= 1
			proofElements += 2
		}
	}
	{
		base := c2PaddedPow2
		res := 1
		for res < base {
			res <<= 1
			proofElements += 2
		}
	}

	c1Root := layers % 2
	c2Root := 1 - c1Root
	c1Branches := (inputs * (layers / 2)) + c1Root
	c2Branches := (inputs * ((layers / 2) - c2Root)) + c2Root

	const WORDS_PER_DLOG = 2
	const WORDS_PER_DIVISOR = 2
	const WORDS_PER_CLAIMED_POINT = WORDS_PER_DLOG + WORDS_PER_DIVISOR

	c1Words := (inputs * (WORDS_PER_DIVISOR + (4 * WORDS_PER_CLAIMED_POINT))) +
		((inputs * ((layers - 1) / 2)) * WORDS_PER_CLAIMED_POINT)
	c2Words := (inputs * (layers / 2)) * WORDS_PER_CLAIMED_POINT

	{
		c1Commitments := c1Branches + utils.DivCeil(c1Words*COMMITMENT_WORD_LEN, c1PaddedPow2)
		ni := 2 + (2 * c1Commitments)
		l_r_poly_len := 1 + ni + 1
		t_poly_len := (2 * l_r_poly_len) - 1
		TCommitments := t_poly_len - (ni / 2) - 1
		proofElements += c1Commitments + TCommitments
	}

	{
		c2Commitments := c2Branches + utils.DivCeil(c2Words*COMMITMENT_WORD_LEN, c2PaddedPow2)
		ni := 2 + (2 * c2Commitments)
		l_r_poly_len := 1 + ni + 1
		t_poly_len := (2 * l_r_poly_len) - 1
		tCommitments := t_poly_len - (ni / 2) - 1
		proofElements += c2Commitments + tCommitments
	}

	return (32 * proofElements) + 64
}
