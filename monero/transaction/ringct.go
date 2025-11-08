package transaction

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/borromean"
	bp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs/original"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/mlsag"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

type Base struct {
	ProofType        ProofType
	Fee              uint64
	PseudoOuts       []curve25519.PublicKeyBytes
	EncryptedAmounts []EncryptedAmount
	Commitments      []curve25519.PublicKeyBytes
}

type EncryptedAmount struct {
	// Mask used with a mask derived from the shared secret to encrypt the amount.
	Mask curve25519.PublicKeyBytes

	// Amount The amount, as a scalar, encrypted.
	Amount [curve25519.PrivateKeySize]byte
}

func (b *Base) Hash() types.Hash {
	data := make([]byte, 0, b.BufferLength())
	var err error
	data, err = b.AppendBinary(data)
	if err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(data)
}

func (b *Base) BufferLength() int {
	n := 1 + utils.UVarInt64Size(b.Fee)
	if b.ProofType == MLSAGBorromean {
		n += curve25519.PublicKeySize * len(b.PseudoOuts)
	}
	if b.ProofType.CompactAmount() {
		n += monero.EncryptedAmountSize * len(b.EncryptedAmounts)
	} else {
		n += (curve25519.PublicKeySize + curve25519.PrivateKeySize) * len(b.EncryptedAmounts)
	}
	n += curve25519.PublicKeySize * len(b.Commitments)
	return n
}

func (b *Base) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := append(preAllocatedBuf, uint8(b.ProofType))
	buf = binary.AppendUvarint(buf, b.Fee)
	if b.ProofType == MLSAGBorromean {
		for _, ps := range b.PseudoOuts {
			buf = append(buf, ps[:]...)
		}
	}
	if b.ProofType.CompactAmount() {
		for _, ea := range b.EncryptedAmounts {
			buf = append(buf, ea.Amount[:monero.EncryptedAmountSize]...)
		}
	} else {
		for _, ea := range b.EncryptedAmounts {
			buf = append(buf, ea.Mask[:]...)
			buf = append(buf, ea.Amount[:]...)
		}
	}
	for _, c := range b.Commitments {
		buf = append(buf, c[:]...)
	}
	return buf, nil
}

func (b *Base) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (err error) {
	var proofType uint8
	if proofType, err = reader.ReadByte(); err != nil {
		return err
	}
	b.ProofType = ProofType(proofType)

	if b.Fee, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}
	if b.ProofType == MLSAGBorromean {
		var ps curve25519.PublicKeyBytes
		for range len(inputs) {
			if _, err = utils.ReadFullNoEscape(reader, ps[:]); err != nil {
				return err
			}
			b.PseudoOuts = append(b.PseudoOuts, ps)
		}
	}
	if b.ProofType.CompactAmount() {
		var amount [curve25519.PrivateKeySize]byte
		for range len(outputs) {
			if _, err = utils.ReadFullNoEscape(reader, amount[:monero.EncryptedAmountSize]); err != nil {
				return err
			}
			b.EncryptedAmounts = append(b.EncryptedAmounts, EncryptedAmount{Amount: amount})
		}
	} else {
		var mask curve25519.PublicKeyBytes
		var amount [curve25519.PrivateKeySize]byte
		for range len(outputs) {
			if _, err = utils.ReadFullNoEscape(reader, mask[:]); err != nil {
				return err
			}
			if _, err = utils.ReadFullNoEscape(reader, amount[:]); err != nil {
				return err
			}
			b.EncryptedAmounts = append(b.EncryptedAmounts, EncryptedAmount{mask, amount})
		}
	}
	var c curve25519.PublicKeyBytes
	for range len(outputs) {
		if _, err = utils.ReadFullNoEscape(reader, c[:]); err != nil {
			return err
		}
		b.Commitments = append(b.Commitments, c)
	}
	return nil
}

type Prunable interface {
	SignatureHash() types.Hash
	Hash(pruned bool) types.Hash
	Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) error
	BufferLength(pruned bool) int
	AppendBinary(preAllocatedBuf []byte, pruned bool) (data []byte, err error)
	// FromReader TODO: support pruned arg
	FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (err error)
}

type PrunableAggregateMLSAGBorromean struct {
	MLSAG     mlsag.Signature[curve25519.VarTimeOperations]
	Borromean []borromean.Range[curve25519.VarTimeOperations]
}

func (p *PrunableAggregateMLSAGBorromean) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	var commitment curve25519.VarTimePublicKey

	var commitments []curve25519.VarTimePublicKey

	// check range proof
	for i, b := range p.Borromean {
		if _, err = commitment.SetBytes(base.Commitments[i][:]); err != nil {
			return err
		}
		if !b.Verify(&commitment) {
			return ErrInvalidBorromeanProof
		}
		commitments = append(commitments, commitment)
	}

	m, err := mlsag.NewRingMatrixFromAggregateRings(base.Fee, commitments, rings...)
	if err != nil {
		return err
	}
	if err = p.MLSAG.Verify(prefixHash, m, images); err != nil {
		return err
	}

	return nil
}

func (p *PrunableAggregateMLSAGBorromean) SignatureHash() types.Hash {
	return p.Hash(true)
}

func (p *PrunableAggregateMLSAGBorromean) Hash(pruned bool) types.Hash {
	buf := make([]byte, 0, p.BufferLength(pruned))
	var err error
	buf, err = p.AppendBinary(buf, pruned)

	if err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableAggregateMLSAGBorromean) BufferLength(pruned bool) (n int) {
	if !pruned {
		n += p.MLSAG.BufferLength()
	}
	for i := range p.Borromean {
		n += p.Borromean[i].BufferLength()
	}
	return n
}

func (p *PrunableAggregateMLSAGBorromean) AppendBinary(preAllocatedBuf []byte, pruned bool) (data []byte, err error) {
	data = preAllocatedBuf
	for _, br := range p.Borromean {
		if data, err = br.AppendBinary(data); err != nil {
			return nil, err
		}
	}
	if !pruned {
		if data, err = p.MLSAG.AppendBinary(data); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (p *PrunableAggregateMLSAGBorromean) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (err error) {
	for range len(outputs) {
		var br borromean.Range[curve25519.VarTimeOperations]
		if err = br.FromReader(reader); err != nil {
			return err
		}
		p.Borromean = append(p.Borromean, br)
	}

	if len(inputs) == 0 {
		return errors.New("empty inputs")
	}

	if err = p.MLSAG.FromReader(reader, len(inputs[0].Offsets), len(inputs)+1); err != nil {
		return err
	}

	return nil
}

type PrunableMLSAGBorromean struct {
	MLSAG     []mlsag.Signature[curve25519.VarTimeOperations]
	Borromean []borromean.Range[curve25519.VarTimeOperations]
}

var ErrInvalidBorromeanProof = errors.New("invalid Borromean proof")
var ErrUnbalancedAmounts = errors.New("unbalanced amounts")

func (p *PrunableMLSAGBorromean) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	var pseudoOut, sumInputs, sumOutputs, commitment curve25519.VarTimePublicKey
	// init
	sumInputs.P().Set(edwards25519.NewIdentityPoint())
	sumOutputs.P().Set(edwards25519.NewIdentityPoint())
	for i, member := range p.MLSAG {
		if _, err = pseudoOut.SetBytes(base.PseudoOuts[i][:]); err != nil {
			return err
		}
		sumInputs.Add(&sumInputs, &pseudoOut)
		m, err := mlsag.NewRingMatrixFromSingle(rings[i], &pseudoOut)
		if err != nil {
			return err
		}
		if err = member.Verify(prefixHash, m, images[i:i+1]); err != nil {
			return err
		}
	}

	// check range proof
	for i, b := range p.Borromean {
		if _, err = commitment.SetBytes(base.Commitments[i][:]); err != nil {
			return err
		}
		sumOutputs.Add(&sumOutputs, &commitment)
		if !b.Verify(&commitment) {
			return ErrInvalidBorromeanProof
		}
	}
	sumOutputs.Add(&sumOutputs, new(curve25519.VarTimePublicKey).ScalarMultPrecomputed(ringct.AmountToScalar(new(curve25519.Scalar), base.Fee), crypto.GeneratorH))

	// check balances
	if sumInputs.Equal(&sumOutputs) == 0 {
		return ErrUnbalancedAmounts
	}
	return nil
}

func (p *PrunableMLSAGBorromean) SignatureHash() types.Hash {
	return p.Hash(true)
}

func (p *PrunableMLSAGBorromean) Hash(pruned bool) types.Hash {
	buf := make([]byte, 0, p.BufferLength(pruned))
	var err error
	if buf, err = p.AppendBinary(buf, pruned); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableMLSAGBorromean) BufferLength(pruned bool) (n int) {
	if !pruned {
		for i := range p.MLSAG {
			n += p.MLSAG[i].BufferLength()
		}
	}
	for i := range p.Borromean {
		n += p.Borromean[i].BufferLength()
	}
	return n
}

func (p *PrunableMLSAGBorromean) AppendBinary(preAllocatedBuf []byte, pruned bool) (data []byte, err error) {
	data = preAllocatedBuf
	for _, br := range p.Borromean {
		if data, err = br.AppendBinary(data); err != nil {
			return nil, err
		}
	}
	if !pruned {
		for _, e := range p.MLSAG {
			if data, err = e.AppendBinary(data); err != nil {
				return nil, err
			}
		}
	}
	return data, nil
}

func (p *PrunableMLSAGBorromean) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (err error) {
	for range len(outputs) {
		var br borromean.Range[curve25519.VarTimeOperations]
		if err = br.FromReader(reader); err != nil {
			return err
		}
		p.Borromean = append(p.Borromean, br)
	}

	for _, i := range inputs {
		var e mlsag.Signature[curve25519.VarTimeOperations]

		if err = e.FromReader(reader, len(i.Offsets), 2); err != nil {
			return err
		}
		p.MLSAG = append(p.MLSAG, e)
	}

	return nil
}

type PrunableMLSAGBulletproofs struct {
	MLSAG []mlsag.Signature[curve25519.VarTimeOperations]
	// PseudoOuts The re-blinded commitments for the outputs being spent.
	PseudoOuts  []curve25519.VarTimePublicKey
	Bulletproof bp.AggregateRangeProof[curve25519.VarTimeOperations]
}

var ErrInvalidBulletproofsProof = errors.New("invalid Bulletproofs proof")

func (p *PrunableMLSAGBulletproofs) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	var sumInputs, sumOutputs curve25519.VarTimePublicKey
	// init
	sumInputs.P().Set(edwards25519.NewIdentityPoint())
	sumOutputs.P().Set(edwards25519.NewIdentityPoint())

	for i, member := range p.MLSAG {
		sumInputs.Add(&sumInputs, &p.PseudoOuts[i])
		m, err := mlsag.NewRingMatrixFromSingle(rings[i], &p.PseudoOuts[i])
		if err != nil {
			return err
		}

		if err = member.Verify(prefixHash, m, images[i:i+1]); err != nil {
			return err
		}
	}

	commitments := make([]curve25519.VarTimePublicKey, len(base.Commitments))
	for i, c := range base.Commitments {
		if _, err = commitments[i].SetBytes(c[:]); err != nil {
			return err
		}
		sumOutputs.Add(&sumOutputs, &commitments[i])
	}

	// check Bulletproof
	if !p.Bulletproof.Verify(commitments, rand.Reader) {
		return ErrInvalidBulletproofsProof
	}

	sumOutputs.Add(&sumOutputs, new(curve25519.VarTimePublicKey).ScalarMultPrecomputed(ringct.AmountToScalar(new(curve25519.Scalar), base.Fee), crypto.GeneratorH))

	// check balances
	if sumInputs.Equal(&sumOutputs) == 0 {
		return ErrUnbalancedAmounts
	}
	return nil
}

func (p *PrunableMLSAGBulletproofs) SignatureHash() types.Hash {
	buf := make([]byte, 0, p.Bulletproof.BufferLength(true))
	var err error
	if buf, err = p.Bulletproof.AppendBinary(buf, true); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableMLSAGBulletproofs) Hash(pruned bool) types.Hash {
	buf := make([]byte, 0, p.BufferLength(pruned))
	var err error
	if buf, err = p.AppendBinary(buf, pruned); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableMLSAGBulletproofs) BufferLength(pruned bool) (n int) {
	if !pruned {
		n += 4
		for i := range p.MLSAG {
			n += p.MLSAG[i].BufferLength()
		}
		n += len(p.PseudoOuts) * curve25519.PublicKeySize
	}
	n += p.Bulletproof.BufferLength(false)
	return n
}

func (p *PrunableMLSAGBulletproofs) AppendBinary(preAllocatedBuf []byte, pruned bool) (data []byte, err error) {
	data = preAllocatedBuf
	if !pruned {
		data = binary.LittleEndian.AppendUint32(data, 1)
	}
	if data, err = p.Bulletproof.AppendBinary(data, false); err != nil {
		return nil, err
	}
	if !pruned {
		for _, e := range p.MLSAG {
			if data, err = e.AppendBinary(data); err != nil {
				return nil, err
			}
		}
		for _, e := range p.PseudoOuts {
			if data, err = e.AppendBinary(data); err != nil {
				return nil, err
			}
		}
	}
	return data, nil
}

func (p *PrunableMLSAGBulletproofs) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (err error) {

	var n uint32
	if err = utils.BinaryReadNoEscape(reader, binary.LittleEndian, &n); err != nil {
		return err
	}

	if n != 1 {
		return errors.New("unexpected n")
	}

	if err = p.Bulletproof.FromReader(reader); err != nil {
		return err
	}

	for _, i := range inputs {
		var e mlsag.Signature[curve25519.VarTimeOperations]

		if err = e.FromReader(reader, len(i.Offsets), 2); err != nil {
			return err
		}
		p.MLSAG = append(p.MLSAG, e)
	}

	var pk curve25519.VarTimePublicKey
	for range inputs {
		if err = pk.FromReader(reader); err != nil {
			return err
		}
		p.PseudoOuts = append(p.PseudoOuts, pk)
	}

	return nil
}

var prunableTypes = []func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (p Prunable, err error){
	nil,
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (p Prunable, err error) {
		var pt PrunableAggregateMLSAGBorromean
		if err = pt.FromReader(reader, inputs, outputs); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (p Prunable, err error) {
		var pt PrunableMLSAGBorromean
		if err = pt.FromReader(reader, inputs, outputs); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (p Prunable, err error) {
		var pt PrunableMLSAGBulletproofs
		if err = pt.FromReader(reader, inputs, outputs); err != nil {
			return nil, err
		}
		return &pt, nil
	},
}
