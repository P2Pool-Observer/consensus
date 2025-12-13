package transaction

import (
	"errors"
	"math/bits"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type TransactionV1 struct {
	Prefix `json:",inline"`

	Signatures RingSignatures `json:"signatures"`
	fee        uint64
}

func (tx *TransactionV1) UnlockTime() uint64 {
	return tx.Prefix.UnlockTime
}

func (tx *TransactionV1) Inputs() Inputs {
	return tx.Prefix.Inputs
}

func (tx *TransactionV1) Outputs() Outputs {
	return tx.Prefix.Outputs
}

func (tx *TransactionV1) Proofs() Proofs {
	return &tx.Signatures
}

func (tx *TransactionV1) Fee() uint64 {
	return tx.fee
}

func (tx *TransactionV1) Weight() int {
	return tx.BufferLength()
}

func (tx *TransactionV1) Version() uint8 {
	return 1
}

func (tx *TransactionV1) Hash() types.Hash {
	buf, err := tx.AppendBinary(make([]byte, 0, tx.BufferLength()))
	if err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(buf)
}

func (tx *TransactionV1) PrefixHash() types.Hash {
	return tx.Prefix.Hash(1)
}

func (tx *TransactionV1) SignatureHash() (out types.Hash) {
	return tx.PrefixHash()
}

func (tx *TransactionV1) ExtraData() []byte {
	return tx.Extra
}

func (tx *TransactionV1) ExtraTags() ExtraTags {
	return tx.Prefix.ExtraTags()
}

func (tx *TransactionV1) PrunedBufferLength() int {
	return 1 + tx.Prefix.BufferLength()
}

func (tx *TransactionV1) BufferLength() int {
	n := 1 + tx.Prefix.BufferLength()
	for _, sig := range tx.Signatures {
		n += sig.BufferLength()
	}
	return n
}

func (tx *TransactionV1) AppendPrunedBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf

	buf = append(buf, 1)
	if buf, err = tx.Prefix.AppendBinary(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func (tx *TransactionV1) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf, err := tx.AppendPrunedBinary(preAllocatedBuf)
	if err != nil {
		return nil, err
	}
	for _, rs := range tx.Signatures {
		if buf, err = rs.AppendBinary(buf); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

var ErrAmountOverflow = errors.New("amount overflow")

func (tx *TransactionV1) FromPrunedReader(reader utils.ReaderAndByteReader) (err error) {
	if err = tx.Prefix.FromReader(reader); err != nil {
		return err
	}

	// verify amounts. checking for over/underflow already verifies proper distribution
	var carry, total uint64
	for _, in := range tx.Inputs() {
		total, carry = bits.Add64(total, in.Amount, 0)
		if carry > 0 {
			return ErrAmountOverflow
		}
	}
	for _, out := range tx.Outputs() {
		if out.Amount > total {
			return ErrAmountOverflow
		}
		total -= out.Amount
	}

	tx.fee = total

	return nil
}

func (tx *TransactionV1) FromReader(reader utils.ReaderAndByteReader) (err error) {
	if err = tx.FromPrunedReader(reader); err != nil {
		return err
	}

	for _, input := range tx.Prefix.Inputs {
		var rs ringct.RingSignature[curve25519.VarTimeOperations]
		if err = rs.FromReader(reader, len(input.Offsets)); err != nil {
			return err
		}
		tx.Signatures = append(tx.Signatures, rs)
	}

	return nil
}
