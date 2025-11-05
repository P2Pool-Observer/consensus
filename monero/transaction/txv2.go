package transaction

import (
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type TransactionV2 struct {
	Prefix
	Base
	Prunable
}

func (tx *TransactionV2) Inputs() Inputs {
	return tx.Prefix.Inputs
}

func (tx *TransactionV2) Outputs() Outputs {
	return tx.Prefix.Outputs
}

type proofV2 struct {
	Base     Base
	Prunable Prunable
}

func (p proofV2) Verify(prefixHash types.Hash, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) error {
	return p.Prunable.Verify(prefixHash, p.Base, rings, images)
}

func (p proofV2) ProofType() ProofType {
	return p.Base.ProofType
}

func (tx *TransactionV2) Proofs() Proofs {
	return proofV2{
		Base:     tx.Base,
		Prunable: tx.Prunable,
	}
}

func (tx *TransactionV2) Fee() uint64 {
	return tx.Base.Fee
}

func (tx *TransactionV2) Version() uint8 {
	return 2
}

func (tx *TransactionV2) Hash() (out types.Hash) {
	crypto.TransactionIdHash(&out, tx.PrefixHash(), tx.Base.Hash(), tx.Prunable.Hash(false))
	return out
}

func (tx *TransactionV2) PrefixHash() types.Hash {
	return tx.Prefix.Hash(2)
}

func (tx *TransactionV2) SignatureHash() (out types.Hash) {
	crypto.TransactionIdHash(&out, tx.PrefixHash(), tx.Base.Hash(), tx.Prunable.Hash(true))
	return out
}

func (tx *TransactionV2) ExtraTags() ExtraTags {
	return tx.Prefix.ExtraTags()
}

func (tx *TransactionV2) BufferLength() int {
	n := 1 + tx.Prefix.BufferLength() + tx.Base.BufferLength() + tx.Prunable.BufferLength(false)
	return n
}

func (tx *TransactionV2) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf

	buf = append(buf, 2)
	if buf, err = tx.Prefix.AppendBinary(buf); err != nil {
		return nil, err
	}
	if buf, err = tx.Base.AppendBinary(buf); err != nil {
		return nil, err
	}
	if buf, err = tx.Prunable.AppendBinary(buf, false); err != nil {
		return nil, err
	}

	return buf, nil
}

func (tx *TransactionV2) FromReader(reader utils.ReaderAndByteReader) (err error) {
	if err = tx.Prefix.FromReader(reader); err != nil {
		return err
	}
	if err = tx.Base.FromReader(reader, tx.Inputs(), tx.Outputs()); err != nil {
		return err
	}

	if int(tx.Base.ProofType) >= len(prunableTypes) || prunableTypes[tx.Base.ProofType] == nil {
		return errors.New("invalid proof type")
	}

	if tx.Prunable, err = prunableTypes[tx.Base.ProofType](reader, tx.Inputs(), tx.Outputs()); err != nil {
		return err
	}

	return nil
}
