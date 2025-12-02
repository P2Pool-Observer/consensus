package transaction

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/borromean"
	bp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs/original"
	bpp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs/plus"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/clsag"
	fcmp_pp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/mlsag"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type Base struct {
	ProofType        ProofType                   `json:"type"`
	Fee              uint64                      `json:"txnFee"`
	PseudoOuts       []curve25519.PublicKeyBytes `json:"pseudoOuts,omitempty"`
	EncryptedAmounts []EncryptedAmount           `json:"ecdhInfo"`
	Commitments      []curve25519.PublicKeyBytes `json:"outPk"`
}

type EncryptedAmount struct {
	// Mask used with a mask derived from the shared secret to encrypt the amount.
	Mask curve25519.PublicKeyBytes `json:"mask"`

	// Amount The amount, as a scalar, encrypted.
	Amount types.FixedBytes[[curve25519.PrivateKeySize]byte] `json:"amount"`
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
			buf = append(buf, ea.Amount.Slice()[:monero.EncryptedAmountSize]...)
		}
	} else {
		for _, ea := range b.EncryptedAmounts {
			buf = append(buf, ea.Mask[:]...)
			buf = append(buf, ea.Amount.Slice()[:]...)
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
		for range inputs {
			if _, err = utils.ReadFullNoEscape(reader, ps[:]); err != nil {
				return err
			}
			b.PseudoOuts = append(b.PseudoOuts, ps)
		}
	}
	if b.ProofType.CompactAmount() {
		var amount [curve25519.PrivateKeySize]byte
		for range outputs {
			if _, err = utils.ReadFullNoEscape(reader, amount[:monero.EncryptedAmountSize]); err != nil {
				return err
			}
			b.EncryptedAmounts = append(b.EncryptedAmounts, EncryptedAmount{Amount: types.MakeFixed(amount)})
		}
	} else {
		var mask curve25519.PublicKeyBytes
		var amount [curve25519.PrivateKeySize]byte
		for range outputs {
			if _, err = utils.ReadFullNoEscape(reader, mask[:]); err != nil {
				return err
			}
			if _, err = utils.ReadFullNoEscape(reader, amount[:]); err != nil {
				return err
			}
			b.EncryptedAmounts = append(b.EncryptedAmounts, EncryptedAmount{mask, types.MakeFixed(amount)})
		}
	}
	var c curve25519.PublicKeyBytes
	for range outputs {
		if _, err = utils.ReadFullNoEscape(reader, c[:]); err != nil {
			return err
		}
		b.Commitments = append(b.Commitments, c)
	}
	return nil
}

type Prunable interface {
	SignatureHash() types.Hash
	Hash(signature bool) types.Hash
	Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) error
	BufferLength(signature bool) int
	AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error)
	// FromReader TODO: support signature arg
	FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error)
}

type PrunableAggregateMLSAGBorromean struct {
	MLSAG     [1]mlsag.Signature[curve25519.VarTimeOperations] `json:"MGs"`
	Borromean []borromean.Range[curve25519.VarTimeOperations]  `json:"rangeSigs"`
}

func (p *PrunableAggregateMLSAGBorromean) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	commitments := make([]curve25519.VarTimePublicKey, len(p.Borromean))

	// check range proof
	for i, b := range p.Borromean {
		if _, err = commitments[i].SetBytes(base.Commitments[i][:]); err != nil {
			return err
		}
		if !b.Verify(&commitments[i]) {
			return ErrInvalidBorromeanProof
		}
	}

	m, err := mlsag.NewRingMatrixFromAggregateRings(base.Fee, commitments, rings...)
	if err != nil {
		return err
	}
	if err = p.MLSAG[0].Verify(prefixHash, m, images); err != nil {
		return err
	}

	return nil
}

func (p *PrunableAggregateMLSAGBorromean) SignatureHash() types.Hash {
	return p.Hash(true)
}

func (p *PrunableAggregateMLSAGBorromean) Hash(signature bool) types.Hash {
	buf := make([]byte, 0, p.BufferLength(signature))
	var err error
	buf, err = p.AppendBinary(buf, signature)

	if err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableAggregateMLSAGBorromean) BufferLength(signature bool) (n int) {
	if !signature {
		n += p.MLSAG[0].BufferLength()
	}
	for i := range p.Borromean {
		n += p.Borromean[i].BufferLength()
	}
	return n
}

func (p *PrunableAggregateMLSAGBorromean) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	data = preAllocatedBuf
	for _, br := range p.Borromean {
		if data, err = br.AppendBinary(data); err != nil {
			return nil, err
		}
	}
	if !signature {
		if data, err = p.MLSAG[0].AppendBinary(data); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (p *PrunableAggregateMLSAGBorromean) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error) {
	for range outputs {
		var br borromean.Range[curve25519.VarTimeOperations]
		if err = br.FromReader(reader); err != nil {
			return err
		}
		p.Borromean = append(p.Borromean, br)
	}

	if len(inputs) == 0 {
		return errors.New("empty inputs")
	}

	if !signature {
		if err = p.MLSAG[0].FromReader(reader, len(inputs[0].Offsets), len(inputs)+1); err != nil {
			return err
		}
	}

	return nil
}

type PrunableMLSAGBorromean struct {
	MLSAG     []mlsag.Signature[curve25519.VarTimeOperations] `json:"MGs"`
	Borromean []borromean.Range[curve25519.VarTimeOperations] `json:"rangeSigs"`
}

var ErrInvalidBorromeanProof = errors.New("invalid Borromean proof")
var ErrUnbalancedAmounts = errors.New("unbalanced amounts")

func (p *PrunableMLSAGBorromean) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	var pseudoOut, sumInputs, sumOutputs, commitment curve25519.VarTimePublicKey
	// init
	sumInputs.Identity()
	sumOutputs.Identity()
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

	sumOutputs.Add(&sumOutputs, ringct.CalculateFeeCommitment(new(curve25519.VarTimePublicKey), base.Fee))

	// check balances
	if sumInputs.Equal(&sumOutputs) == 0 {
		return ErrUnbalancedAmounts
	}
	return nil
}

func (p *PrunableMLSAGBorromean) SignatureHash() types.Hash {
	return p.Hash(true)
}

func (p *PrunableMLSAGBorromean) Hash(signature bool) types.Hash {
	buf := make([]byte, 0, p.BufferLength(signature))
	var err error
	if buf, err = p.AppendBinary(buf, signature); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableMLSAGBorromean) BufferLength(signature bool) (n int) {
	if !signature {
		for i := range p.MLSAG {
			n += p.MLSAG[i].BufferLength()
		}
	}
	for i := range p.Borromean {
		n += p.Borromean[i].BufferLength()
	}
	return n
}

func (p *PrunableMLSAGBorromean) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	data = preAllocatedBuf
	for _, br := range p.Borromean {
		if data, err = br.AppendBinary(data); err != nil {
			return nil, err
		}
	}
	if !signature {
		for _, e := range p.MLSAG {
			if data, err = e.AppendBinary(data); err != nil {
				return nil, err
			}
		}
	}
	return data, nil
}

func (p *PrunableMLSAGBorromean) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error) {
	for range outputs {
		var br borromean.Range[curve25519.VarTimeOperations]
		if err = br.FromReader(reader); err != nil {
			return err
		}
		p.Borromean = append(p.Borromean, br)
	}

	if !signature {
		for _, i := range inputs {
			var e mlsag.Signature[curve25519.VarTimeOperations]

			if err = e.FromReader(reader, len(i.Offsets), 2); err != nil {
				return err
			}
			p.MLSAG = append(p.MLSAG, e)
		}
	}

	return nil
}

type PrunableMLSAGBulletproofs struct {
	MLSAG []mlsag.Signature[curve25519.VarTimeOperations]
	// PseudoOuts The re-blinded commitments for the outputs being spent.
	PseudoOuts  []curve25519.VarTimePublicKey
	Bulletproof bp.AggregateRangeProof[curve25519.VarTimeOperations]
}

func (p *PrunableMLSAGBulletproofs) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	return pSigRangeProofVerifyMLSAG(p.MLSAG, p.PseudoOuts, &p.Bulletproof, prefixHash, base, rings, images)
}

func (p *PrunableMLSAGBulletproofs) SignatureHash() types.Hash {
	return pSigRangeProofSignatureHash(&p.Bulletproof)
}

func (p *PrunableMLSAGBulletproofs) Hash(signature bool) types.Hash {
	buf := make([]byte, 0, p.BufferLength(signature))
	var err error
	if buf, err = p.AppendBinary(buf, signature); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableMLSAGBulletproofs) BufferLength(signature bool) (n int) {
	if !signature {
		n += 4
		for i := range p.MLSAG {
			n += p.MLSAG[i].BufferLength()
		}
		n += len(p.PseudoOuts) * curve25519.PublicKeySize
	}
	n += p.Bulletproof.BufferLength(false)
	return n
}

func (p *PrunableMLSAGBulletproofs) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	data = preAllocatedBuf
	if !signature {
		data = binary.LittleEndian.AppendUint32(data, 1)
	}
	if data, err = p.Bulletproof.AppendBinary(data, false); err != nil {
		return nil, err
	}
	if !signature {
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

func (p *PrunableMLSAGBulletproofs) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error) {

	var n uint32

	if !signature {
		if err = utils.BinaryReadNoEscape(reader, binary.LittleEndian, &n); err != nil {
			return err
		}

		if n != 1 {
			return errors.New("unexpected n")
		}
	}

	if err = p.Bulletproof.FromReader(reader); err != nil {
		return err
	}

	if !signature {
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
	}

	return nil
}

type PrunableMLSAGBulletproofsCompactAmount struct {
	MLSAG []mlsag.Signature[curve25519.VarTimeOperations]
	// PseudoOuts The re-blinded commitments for the outputs being spent.
	PseudoOuts  []curve25519.VarTimePublicKey
	Bulletproof bp.AggregateRangeProof[curve25519.VarTimeOperations]
}

func (p *PrunableMLSAGBulletproofsCompactAmount) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	return pSigRangeProofVerifyMLSAG(p.MLSAG, p.PseudoOuts, &p.Bulletproof, prefixHash, base, rings, images)
}

func (p *PrunableMLSAGBulletproofsCompactAmount) SignatureHash() types.Hash {
	return pSigRangeProofSignatureHash(&p.Bulletproof)
}

func (p *PrunableMLSAGBulletproofsCompactAmount) Hash(signature bool) types.Hash {
	return pSigRangeProofHash(p.MLSAG, p.PseudoOuts, &p.Bulletproof, signature)
}

func (p *PrunableMLSAGBulletproofsCompactAmount) BufferLength(signature bool) (n int) {
	return pSigRangeProofBufferLength(p.MLSAG, p.PseudoOuts, &p.Bulletproof, signature)
}

func (p *PrunableMLSAGBulletproofsCompactAmount) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	return pSigRangeProofAppendBinary(p.MLSAG, p.PseudoOuts, &p.Bulletproof, preAllocatedBuf, signature)
}

func (p *PrunableMLSAGBulletproofsCompactAmount) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error) {
	return pSigRangeProofFromReaderMLSAG(&p.MLSAG, &p.PseudoOuts, &p.Bulletproof, reader, inputs, signature)
}

type PrunableCLSAGBulletproofs struct {
	CLSAG []clsag.Signature[curve25519.VarTimeOperations]
	// PseudoOuts The re-blinded commitments for the outputs being spent.
	PseudoOuts  []curve25519.VarTimePublicKey
	Bulletproof bp.AggregateRangeProof[curve25519.VarTimeOperations]
}

func (p *PrunableCLSAGBulletproofs) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	return pSigRangeProofVerifyCLSAG(p.CLSAG, p.PseudoOuts, &p.Bulletproof, prefixHash, base, rings, images)
}

func (p *PrunableCLSAGBulletproofs) SignatureHash() types.Hash {
	return pSigRangeProofSignatureHash(&p.Bulletproof)
}

func (p *PrunableCLSAGBulletproofs) Hash(signature bool) types.Hash {
	return pSigRangeProofHash(p.CLSAG, p.PseudoOuts, &p.Bulletproof, signature)
}

func (p *PrunableCLSAGBulletproofs) BufferLength(signature bool) (n int) {
	return pSigRangeProofBufferLength(p.CLSAG, p.PseudoOuts, &p.Bulletproof, signature)
}

func (p *PrunableCLSAGBulletproofs) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	return pSigRangeProofAppendBinary(p.CLSAG, p.PseudoOuts, &p.Bulletproof, preAllocatedBuf, signature)
}

func (p *PrunableCLSAGBulletproofs) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error) {
	return pSigRangeProofFromReaderCLSAG(&p.CLSAG, &p.PseudoOuts, &p.Bulletproof, reader, inputs, signature)
}

type PrunableCLSAGBulletproofsPlus struct {
	CLSAG []clsag.Signature[curve25519.VarTimeOperations]
	// PseudoOuts The re-blinded commitments for the outputs being spent.
	PseudoOuts  []curve25519.VarTimePublicKey
	Bulletproof bpp.AggregateRangeProof[curve25519.VarTimeOperations]
}

func (p *PrunableCLSAGBulletproofsPlus) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	return pSigRangeProofVerifyCLSAG(p.CLSAG, p.PseudoOuts, &p.Bulletproof, prefixHash, base, rings, images)
}

func (p *PrunableCLSAGBulletproofsPlus) SignatureHash() types.Hash {
	return pSigRangeProofSignatureHash(&p.Bulletproof)
}

func (p *PrunableCLSAGBulletproofsPlus) Hash(signature bool) types.Hash {
	return pSigRangeProofHash(p.CLSAG, p.PseudoOuts, &p.Bulletproof, signature)
}

func (p *PrunableCLSAGBulletproofsPlus) BufferLength(signature bool) (n int) {
	return pSigRangeProofBufferLength(p.CLSAG, p.PseudoOuts, &p.Bulletproof, signature)
}

func (p *PrunableCLSAGBulletproofsPlus) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	return pSigRangeProofAppendBinary(p.CLSAG, p.PseudoOuts, &p.Bulletproof, preAllocatedBuf, signature)
}

func (p *PrunableCLSAGBulletproofsPlus) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error) {
	return pSigRangeProofFromReaderCLSAG(&p.CLSAG, &p.PseudoOuts, &p.Bulletproof, reader, inputs, signature)
}

type pSig[S any] interface {
	*S
	AppendBinary(preAllocatedBuf []byte) (data []byte, err error)
	BufferLength() int
}

type pRangeProof[RP any] interface {
	*RP
	Verify(commitments []curve25519.PublicKey[curve25519.VarTimeOperations], randomReader io.Reader) bool
	AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error)
	FromReader(reader utils.ReaderAndByteReader) (err error)
	BufferLength(signature bool) int
}

var ErrInvalidRangeProof = errors.New("invalid range proof")

func pSigRangeProofVerifyCLSAG[RP any, pRP pRangeProof[RP]](sigs []clsag.Signature[curve25519.VarTimeOperations], pseudoOuts []curve25519.VarTimePublicKey, rangeProof *RP, prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	var sumInputs, sumOutputs curve25519.VarTimePublicKey
	// init
	sumInputs.Identity()
	sumOutputs.Identity()

	for i, member := range sigs {
		sumInputs.Add(&sumInputs, &pseudoOuts[i])

		if err = member.Verify(prefixHash, rings[i], &images[i], &pseudoOuts[i]); err != nil {
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

	// check range proof
	if !pRP(rangeProof).Verify(commitments, rand.Reader) {
		return ErrInvalidRangeProof
	}

	sumOutputs.Add(&sumOutputs, ringct.CalculateFeeCommitment(new(curve25519.VarTimePublicKey), base.Fee))

	// check balances
	if sumInputs.Equal(&sumOutputs) == 0 {
		return ErrUnbalancedAmounts
	}
	return nil
}

func pSigRangeProofVerifyMLSAG[RP any, pRP pRangeProof[RP]](sigs []mlsag.Signature[curve25519.VarTimeOperations], pseudoOuts []curve25519.VarTimePublicKey, rangeProof *RP, prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	var sumInputs, sumOutputs curve25519.VarTimePublicKey
	// init
	sumInputs.Identity()
	sumOutputs.Identity()

	for i, member := range sigs {
		sumInputs.Add(&sumInputs, &pseudoOuts[i])
		m, err := mlsag.NewRingMatrixFromSingle(rings[i], &pseudoOuts[i])
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

	// check range proof
	if !pRP(rangeProof).Verify(commitments, rand.Reader) {
		return ErrInvalidRangeProof
	}

	sumOutputs.Add(&sumOutputs, ringct.CalculateFeeCommitment(new(curve25519.VarTimePublicKey), base.Fee))

	// check balances
	if sumInputs.Equal(&sumOutputs) == 0 {
		return ErrUnbalancedAmounts
	}
	return nil
}

func pSigRangeProofSignatureHash[RP any, pRP pRangeProof[RP]](rangeProof *RP) types.Hash {
	buf := make([]byte, 0, pRP(rangeProof).BufferLength(true))
	var err error
	if buf, err = pRP(rangeProof).AppendBinary(buf, true); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func pSigRangeProofHash[S any, RP any, pS pSig[S], pRP pRangeProof[RP]](sigs []S, pseudoOuts []curve25519.VarTimePublicKey, rangeProof *RP, signature bool) types.Hash {
	buf := make([]byte, 0, pSigRangeProofBufferLength[S, RP, pS, pRP](sigs, pseudoOuts, rangeProof, signature))
	var err error
	if buf, err = pSigRangeProofAppendBinary[S, RP, pS, pRP](sigs, pseudoOuts, rangeProof, buf, signature); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func pSigRangeProofBufferLength[S any, RP any, pS pSig[S], pRP pRangeProof[RP]](sigs []S, pseudoOuts []curve25519.VarTimePublicKey, rangeProof *RP, signature bool) (n int) {
	if !signature {
		n += 1
		for i := range sigs {
			n += pS(&sigs[i]).BufferLength()
		}
		n += len(pseudoOuts) * curve25519.PublicKeySize
	}
	n += pRP(rangeProof).BufferLength(false)
	return n
}

func pSigRangeProofAppendBinary[S any, RP any, pS pSig[S], pRP pRangeProof[RP]](sigs []S, pseudoOuts []curve25519.VarTimePublicKey, rangeProof *RP, preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	data = preAllocatedBuf
	if !signature {
		// this is the same on varint than byte encodings
		data = append(data, 1)
	}
	if data, err = pRP(rangeProof).AppendBinary(data, false); err != nil {
		return nil, err
	}
	if !signature {
		for _, e := range sigs {
			if data, err = pS(&e).AppendBinary(data); err != nil {
				return nil, err
			}
		}
		for _, e := range pseudoOuts {
			if data, err = e.AppendBinary(data); err != nil {
				return nil, err
			}
		}
	}
	return data, nil
}

func pSigRangeProofFromReaderCLSAG[RP any, pRP pRangeProof[RP]](sigs *[]clsag.Signature[curve25519.VarTimeOperations], pseudoOuts *[]curve25519.VarTimePublicKey, rangeProof *RP, reader utils.ReaderAndByteReader, inputs Inputs, signature bool) (err error) {
	var n uint8
	if !signature {
		if n, err = reader.ReadByte(); err != nil {
			return err
		}

		if n != 1 {
			return errors.New("unexpected n")
		}
	}

	if err = pRP(rangeProof).FromReader(reader); err != nil {
		return err
	}

	if !signature {
		for _, i := range inputs {
			var e clsag.Signature[curve25519.VarTimeOperations]

			if err = e.FromReader(reader, len(i.Offsets)); err != nil {
				return err
			}
			*sigs = append(*sigs, e)
		}

		var pk curve25519.VarTimePublicKey
		for range inputs {
			if err = pk.FromReader(reader); err != nil {
				return err
			}
			*pseudoOuts = append(*pseudoOuts, pk)
		}
	}

	return nil
}

func pSigRangeProofFromReaderMLSAG[RP any, pRP pRangeProof[RP]](sigs *[]mlsag.Signature[curve25519.VarTimeOperations], pseudoOuts *[]curve25519.VarTimePublicKey, rangeProof *RP, reader utils.ReaderAndByteReader, inputs Inputs, signature bool) (err error) {

	var n uint64
	if !signature {
		if n, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		if n != 1 {
			return errors.New("unexpected n")
		}
	}

	if err = pRP(rangeProof).FromReader(reader); err != nil {
		return err
	}

	if !signature {
		for _, i := range inputs {
			var e mlsag.Signature[curve25519.VarTimeOperations]

			if err = e.FromReader(reader, len(i.Offsets), 2); err != nil {
				return err
			}
			*sigs = append(*sigs, e)
		}

		var pk curve25519.VarTimePublicKey
		for range inputs {
			if err = pk.FromReader(reader); err != nil {
				return err
			}
			*pseudoOuts = append(*pseudoOuts, pk)
		}
	}

	return nil
}

type PrunableFCMPPlusPlus struct {
	// ReferenceBlock used to get the tree root as of when this reference block index enters the chain
	ReferenceBlock uint64
	// NTreeLayers number of layers in the tree as of the block when the reference block index enters the chain
	NTreeLayers uint8
	// FCMP_PP FCMP++ SAL and membership proof
	FCMP_PP []byte
	// PseudoOuts The re-blinded commitments for the outputs being spent.
	PseudoOuts  []curve25519.VarTimePublicKey
	Bulletproof bpp.AggregateRangeProof[curve25519.VarTimeOperations]
}

func (p *PrunableFCMPPlusPlus) Verify(prefixHash types.Hash, base Base, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) (err error) {
	var sumInputs, sumOutputs curve25519.VarTimePublicKey
	// init
	sumInputs.Identity()
	sumOutputs.Identity()

	// TODO: verify FCMP++
	{

	}

	for i := range p.PseudoOuts {
		sumInputs.Add(&sumInputs, &p.PseudoOuts[i])
	}

	commitments := make([]curve25519.VarTimePublicKey, len(base.Commitments))
	for i, c := range base.Commitments {
		if _, err = commitments[i].SetBytes(c[:]); err != nil {
			return err
		}
		sumOutputs.Add(&sumOutputs, &commitments[i])
	}

	// check Bulletproof+
	if !p.Bulletproof.Verify(commitments, rand.Reader) {
		return ErrInvalidRangeProof
	}

	sumOutputs.Add(&sumOutputs, ringct.CalculateFeeCommitment(new(curve25519.VarTimePublicKey), base.Fee))

	// check balances
	if sumInputs.Equal(&sumOutputs) == 0 {
		return ErrUnbalancedAmounts
	}
	return nil
}

func (p *PrunableFCMPPlusPlus) SignatureHash() types.Hash {
	buf := make([]byte, 0, p.Bulletproof.BufferLength(true))
	var err error
	if buf, err = p.Bulletproof.AppendBinary(buf, true); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableFCMPPlusPlus) Hash(signature bool) types.Hash {
	buf := make([]byte, 0, p.BufferLength(signature))
	var err error
	if buf, err = p.AppendBinary(buf, signature); err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (p *PrunableFCMPPlusPlus) BufferLength(signature bool) (n int) {
	if !signature {
		n += 1
		n += utils.UVarInt64Size(p.ReferenceBlock) + 1 + len(p.FCMP_PP)
		n += len(p.PseudoOuts) * curve25519.PublicKeySize
	}
	n += p.Bulletproof.BufferLength(false)
	return n
}

func (p *PrunableFCMPPlusPlus) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	data = preAllocatedBuf
	if !signature {
		data = append(data, 1)
	}
	if data, err = p.Bulletproof.AppendBinary(data, false); err != nil {
		return nil, err
	}
	if !signature {
		data = binary.AppendUvarint(data, p.ReferenceBlock)
		data = append(data, p.NTreeLayers)
		data = append(data, p.FCMP_PP...)

		for _, e := range p.PseudoOuts {
			if data, err = e.AppendBinary(data); err != nil {
				return nil, err
			}
		}
	}
	return data, nil
}

func (p *PrunableFCMPPlusPlus) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (err error) {

	var n uint8
	if !signature {
		if n, err = reader.ReadByte(); err != nil {
			return err
		}

		if n != 1 {
			return errors.New("unexpected n")
		}

	}

	if err = p.Bulletproof.FromReader(reader); err != nil {
		return err
	}

	if !signature {
		if p.ReferenceBlock, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		// n_tree_layers can be inferred from the reference_block, however, if we didn't save n_tree_layers on the
		// tx, we would need a db read (for n_tree_layers as of the block) in order to de-serialize the FCMP++ proof
		if p.NTreeLayers, err = reader.ReadByte(); err != nil {
			return err
		}

		if len(inputs) == 0 || len(inputs) > fcmp_pp.MaxInputs {
			return errors.New("unsupported number of inputs")
		}

		if p.NTreeLayers == 0 || p.NTreeLayers > fcmp_pp.MaxLayers {
			return errors.New("unsupported number of layers")
		}

		proofSize := fcmp_pp.ProofSize(len(inputs), int(p.NTreeLayers))
		p.FCMP_PP = make([]byte, proofSize)
		if _, err = utils.ReadFullNoEscape(reader, p.FCMP_PP); err != nil {
			return err
		}

		var pk curve25519.VarTimePublicKey
		for range inputs {
			if err = pk.FromReader(reader); err != nil {
				return err
			}
			p.PseudoOuts = append(p.PseudoOuts, pk)
		}
	}

	return nil
}

var prunableTypes = []func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error){
	nil,
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error) {
		var pt PrunableAggregateMLSAGBorromean
		if err = pt.FromReader(reader, inputs, outputs, signature); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error) {
		var pt PrunableMLSAGBorromean
		if err = pt.FromReader(reader, inputs, outputs, signature); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error) {
		var pt PrunableMLSAGBulletproofs
		if err = pt.FromReader(reader, inputs, outputs, signature); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error) {
		var pt PrunableMLSAGBulletproofsCompactAmount
		if err = pt.FromReader(reader, inputs, outputs, signature); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error) {
		var pt PrunableCLSAGBulletproofs
		if err = pt.FromReader(reader, inputs, outputs, signature); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error) {
		var pt PrunableCLSAGBulletproofsPlus
		if err = pt.FromReader(reader, inputs, outputs, signature); err != nil {
			return nil, err
		}
		return &pt, nil
	},
	func(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs, signature bool) (p Prunable, err error) {
		var pt PrunableFCMPPlusPlus
		if err = pt.FromReader(reader, inputs, outputs, signature); err != nil {
			return nil, err
		}
		return &pt, nil
	},
}
