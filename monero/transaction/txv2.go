package transaction

import (
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
	fcmp_pp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type TransactionV2 struct {
	Prefix   `json:",inline"`
	Base     `json:"rct_signatures"`
	Prunable `json:"rctsig_prunable"`
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
	if p.Prunable == nil {
		return errors.New("nil prunable")
	}
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

func (tx *TransactionV2) Weight() int {
	if tx.ProofType == FCMPPlusPlus {
		return fcmp_pp.TransactionWeightV1(len(tx.Inputs()), len(tx.Outputs()), len(tx.Extra))
	}
	if tx.Prunable == nil {
		return 0
	}
	weight := tx.BufferLength()
	if tx.ProofType.Bulletproof() || tx.ProofType.BulletproofPlus() {
		clawback, _ := bulletproofs.CalculateClawback(tx.ProofType.BulletproofPlus(), len(tx.Outputs()))
		weight += clawback
	}

	return weight
}

func (tx *TransactionV2) Version() uint8 {
	return 2
}

func (tx *TransactionV2) Hash() (out types.Hash) {
	if tx.Prunable == nil {
		return types.ZeroHash
	}
	crypto.TransactionIdHash(&out, tx.PrefixHash(), tx.Base.Hash(), tx.Prunable.Hash(false))
	return out
}

func (tx *TransactionV2) PrefixHash() types.Hash {
	return tx.Prefix.Hash(2)
}

func (tx *TransactionV2) SignatureHash() (out types.Hash) {
	if tx.ProofType == FCMPPlusPlus {
		// Don't hash range proof data to enable cleaner separation of SAL signature <> membership proof <> range proof
		crypto.SignableFCMPTransactionHash(&out, tx.PrefixHash(), tx.Base.Hash())
		return out
	}
	if tx.Prunable == nil {
		return types.ZeroHash
	}
	crypto.TransactionIdHash(&out, tx.PrefixHash(), tx.Base.Hash(), tx.Prunable.SignatureHash())
	return out
}

func (tx *TransactionV2) ExtraTags() ExtraTags {
	return tx.Prefix.ExtraTags()
}

func (tx *TransactionV2) BufferLength() int {
	if tx.Prunable == nil {
		return 0
	}
	n := 1 + tx.Prefix.BufferLength() + tx.Base.BufferLength() + tx.Prunable.BufferLength(false)
	return n
}

func (tx *TransactionV2) PrunedBufferLength() int {
	n := 1 + tx.Prefix.BufferLength() + tx.Base.BufferLength()
	return n
}

func (tx *TransactionV2) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf, err := tx.AppendPrunedBinary(preAllocatedBuf)
	if err != nil {
		return nil, err
	}

	if tx.Prunable == nil {
		return nil, errors.New("pruned transaction")
	}

	if buf, err = tx.Prunable.AppendBinary(buf, false); err != nil {
		return nil, err
	}

	return buf, nil
}

func (tx *TransactionV2) AppendPrunedBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf

	buf = append(buf, 2)
	if buf, err = tx.Prefix.AppendBinary(buf); err != nil {
		return nil, err
	}
	if buf, err = tx.Base.AppendBinary(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func (tx *TransactionV2) FromPrunedReader(reader utils.ReaderAndByteReader) (err error) {
	if err = tx.Prefix.FromReader(reader); err != nil {
		return err
	}
	if err = tx.Base.FromReader(reader, tx.Inputs(), tx.Outputs()); err != nil {
		return err
	}

	if int(tx.ProofType) >= len(prunableTypes) || prunableTypes[tx.ProofType] == nil {
		return errors.New("invalid proof type")
	}

	return nil
}

func (tx *TransactionV2) FromReader(reader utils.ReaderAndByteReader) (err error) {
	if err = tx.FromPrunedReader(reader); err != nil {
		return err
	}

	if tx.Prunable, err = prunableTypes[tx.ProofType](reader, tx.Inputs(), tx.Outputs(), false); err != nil {
		return err
	}

	return nil
}
