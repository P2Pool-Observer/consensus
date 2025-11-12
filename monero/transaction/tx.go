package transaction

import (
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type Prefix struct {
	UnlockTime uint64           `json:"unlock_time"`
	Inputs     Inputs           `json:"vin"`
	Outputs    Outputs          `json:"vout"`
	Extra      types.SliceBytes `json:"extra"`
}

type InputToKey struct {
	Amount   uint64                    `json:"amount"`
	Offsets  []uint64                  `json:"key_offsets"`
	KeyImage curve25519.PublicKeyBytes `json:"k_image"`
}

type itk struct {
	Key InputToKey `json:"key"`
}

func (i *InputToKey) BufferLength() int {
	return 1 + utils.UVarInt64Size(i.Amount) + utils.UVarInt64Size(len(i.Offsets)) + utils.UVarInt64SliceSize(i.Offsets) + curve25519.PublicKeySize
}

func (i *InputToKey) MarshalJSON() ([]byte, error) {
	ik := itk{
		Key: *i,
	}
	return utils.MarshalJSON(ik)
}

func (i *InputToKey) UnmarshalJSON(b []byte) error {
	var ik itk
	if err := utils.UnmarshalJSON(b, &ik); err != nil {
		return err
	}

	*i = ik.Key

	if i.KeyImage == curve25519.ZeroPublicKeyBytes || len(i.Offsets) == 0 {
		return errors.New("invalid input")
	}

	return nil
}

type Inputs []InputToKey

func (i *Inputs) BufferLength() (n int) {
	n = utils.UVarInt64Size(len(*i))
	for _, i := range *i {
		n += i.BufferLength()
	}
	return n
}

func (i *Inputs) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	data = preAllocatedBuf

	data = binary.AppendUvarint(data, uint64(len(*i)))

	for _, i := range *i {
		data = append(data, TxInToKey)
		data = binary.AppendUvarint(data, i.Amount)
		data = binary.AppendUvarint(data, uint64(len(i.Offsets)))
		for _, o := range i.Offsets {
			data = binary.AppendUvarint(data, o)
		}
		data = append(data, i.KeyImage[:]...)
	}
	return data, nil
}

func (i *Inputs) FromReader(reader utils.ReaderAndByteReader) (err error) {
	var inputCount, offsetsCount, offset uint64
	if inputCount, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	var inputType uint8
	for range inputCount {
		if inputType, err = utils.ReadByteNoEscape(reader); err != nil {
			return err
		}

		if inputType != TxInToKey {
			return errors.New("invalid input type")
		}

		var input InputToKey
		if input.Amount, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}
		if offsetsCount, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}
		for range offsetsCount {
			if offset, err = utils.ReadCanonicalUvarint(reader); err != nil {
				return err
			}
			input.Offsets = append(input.Offsets, offset)
		}

		if _, err = utils.ReadFullNoEscape(reader, input.KeyImage[:]); err != nil {
			return err
		}
		*i = append(*i, input)
	}
	return nil
}

func (p *Prefix) ExtraTags() ExtraTags {
	var extraTags ExtraTags
	if err := extraTags.UnmarshalBinary(p.Extra); err != nil {
		return nil
	}
	return extraTags
}

func (p *Prefix) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf

	buf = binary.AppendUvarint(buf, p.UnlockTime)

	if buf, err = p.Inputs.AppendBinary(buf); err != nil {
		return nil, err
	}

	if buf, err = p.Outputs.AppendBinary(buf); err != nil {
		return nil, err
	}

	buf = binary.AppendUvarint(buf, uint64(len(p.Extra)))
	buf = append(buf, p.Extra...)

	return buf, nil
}

func (p *Prefix) FromReader(reader utils.ReaderAndByteReader) (err error) {
	var (
		txExtraSize uint64
	)

	if p.UnlockTime, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if err = p.Inputs.FromReader(reader); err != nil {
		return err
	}

	if err = p.Outputs.FromReader(reader); err != nil {
		return err
	}

	if txExtraSize, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	limitReader := utils.LimitByteReader(reader, int64(txExtraSize))

	if _, err = utils.ReadFullProgressive(limitReader, &p.Extra, int(txExtraSize)); err != nil {
		return err
	}

	if limitReader.Left() > 0 {
		return errors.New("bytes leftover in extra data")
	}

	return nil
}

// Hash Equivalent to get_transaction_prefix_hash
func (p *Prefix) Hash(version uint8) types.Hash {
	data := make([]byte, 0, 1+p.BufferLength())
	data = append(data, version)
	var err error
	data, err = p.AppendBinary(data)
	if err != nil {
		return types.ZeroHash
	}
	return crypto.Keccak256(data)
}

func (p *Prefix) BufferLength() int {
	return utils.UVarInt64Size(p.UnlockTime) +
		p.Inputs.BufferLength() +
		p.Outputs.BufferLength() +
		utils.UVarInt64Size(len(p.Extra)) + len(p.Extra)
}

type Transaction interface {
	Version() uint8
	Hash() types.Hash
	PrefixHash() types.Hash
	SignatureHash() types.Hash
	BufferLength() int
	Fee() uint64
	Weight() int
	Inputs() Inputs
	Outputs() Outputs
	Proofs() Proofs
	ExtraTags() ExtraTags
	AppendBinary(preAllocatedBuf []byte) (data []byte, err error)
}

type PrunableTransaction interface {
	Transaction
	SignatureHash() types.Hash
}

func NewTransactionFromReader(reader utils.ReaderAndByteReader) (tx PrunableTransaction, err error) {
	var version uint8

	if version, err = reader.ReadByte(); err != nil {
		return nil, err
	}

	switch version {
	case 1:
		var txV1 TransactionV1
		if err = txV1.FromReader(reader); err != nil {
			return nil, err
		}
		return &txV1, nil
	case 2:
		var txV2 TransactionV2
		if err = txV2.FromReader(reader); err != nil {
			return nil, err
		}
		return &txV2, nil
	default:
		return nil, errors.New("unsupported version")
	}
}
