package transaction

import (
	"bytes"
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type CoinbaseV2 struct {
	// UnlockTime would be here
	InputCount uint8 `json:"input_count"`
	InputType  uint8 `json:"input_type"`
	// UnlockTime re-arranged here to improve memory layout space
	UnlockTime   uint64  `json:"unlock_time"`
	GenHeight    uint64  `json:"gen_height"`
	MinerOutputs Outputs `json:"outputs"`

	Extra ExtraTags `json:"extra"`

	ExtraBaseRCT uint8 `json:"extra_base_rct"`

	// AuxiliaryData Used by p2pool serialized pruned blocks
	AuxiliaryData CoinbaseTransactionAuxiliaryData `json:"auxiliary_data"`
}

type CoinbaseTransactionAuxiliaryData struct {
	// OutputsBlobSize length of serialized Outputs. Used by p2pool serialized pruned blocks, filled regardless
	OutputsBlobSize uint64 `json:"outputs_blob_size"`
	// TotalReward amount of reward existing Outputs. Used by p2pool serialized pruned blocks, filled regardless
	TotalReward uint64 `json:"total_reward"`
	// TemplateId Required by sidechain.GetOutputs to speed up repeated broadcasts from different peers
	// This must be filled when preprocessing
	TemplateId types.Hash `json:"template_id,omitempty"`
}

func (c *CoinbaseV2) UnmarshalBinary(data []byte, canBePruned, containsAuxiliaryTemplateId bool) error {
	reader := bytes.NewReader(data)
	err := c.FromReader(reader, canBePruned, containsAuxiliaryTemplateId)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}

var ErrInvalidTransactionExtra = errors.New("invalid transaction extra")

func (c *CoinbaseV2) Fee() uint64 {
	return 0
}

func (c *CoinbaseV2) Weight() int {
	return c.BufferLength()
}

func (c *CoinbaseV2) ExtraTags() ExtraTags {
	return c.Extra
}

func (c *CoinbaseV2) Proofs() Proofs {
	return nil
}

func (c *CoinbaseV2) PrefixHash() types.Hash {
	prefixBytes, _ := c.AppendBinary(make([]byte, 0, c.BufferLength()))
	return crypto.Keccak256(prefixBytes[:len(prefixBytes)-1])
}

func (c *CoinbaseV2) SignatureHash() types.Hash {
	return c.Hash()
}

func (c *CoinbaseV2) Inputs() Inputs {
	return nil
}

func (c *CoinbaseV2) Outputs() Outputs {
	return c.MinerOutputs
}

func (c *CoinbaseV2) Version() uint8 {
	return 2
}

// FromVersionReader Internal version to skip version check
func (c *CoinbaseV2) FromVersionReader(reader utils.ReaderAndByteReader, canBePruned, containsAuxiliaryTemplateId bool) (err error) {
	var (
		txExtraSize uint64
	)

	c.AuxiliaryData.TotalReward = 0
	c.AuxiliaryData.OutputsBlobSize = 0

	if c.UnlockTime, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if c.InputCount, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if c.InputCount != 1 {
		return errors.New("invalid input count")
	}

	if c.InputType, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if c.InputType != TxInGen {
		return errors.New("invalid coinbase input type")
	}

	if c.GenHeight, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if c.UnlockTime != (c.GenHeight + monero.MinerRewardUnlockTime) {
		return errors.New("invalid unlock time")
	}

	if err = c.MinerOutputs.FromReader(reader); err != nil {
		return err
	} else if len(c.MinerOutputs) != 0 {
		for _, o := range c.MinerOutputs {
			switch o.Type {
			case TxOutToCarrotV1:
				c.AuxiliaryData.OutputsBlobSize += 1 + types.HashSize + monero.CarrotViewTagSize + monero.JanusAnchorSize
			case TxOutToTaggedKey:
				c.AuxiliaryData.OutputsBlobSize += 1 + types.HashSize + 1
			case TxOutToKey:
				c.AuxiliaryData.OutputsBlobSize += 1 + types.HashSize
			default:
				return utils.ErrorfNoEscape("unknown %d TXOUT key", o.Type)
			}
			c.AuxiliaryData.TotalReward += o.Amount
		}
	} else {
		if !canBePruned {
			return errors.New("pruned outputs not supported")
		}

		// MinerOutputs are not in the buffer and must be calculated from sidechain data
		// We only have total reward and outputs blob size here
		//special case, pruned block. outputs have to be generated from chain

		if c.AuxiliaryData.TotalReward, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		if c.AuxiliaryData.OutputsBlobSize, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		if containsAuxiliaryTemplateId {
			// Required by sidechain.get_outputs_blob() to speed up repeated broadcasts from different peers
			if _, err = utils.ReadFullNoEscape(reader, c.AuxiliaryData.TemplateId[:]); err != nil {
				return err
			}
		}
	}

	if txExtraSize, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	limitReader := utils.LimitByteReader(reader, int64(txExtraSize))
	if err = c.Extra.FromReader(limitReader); err != nil {
		return errors.Join(ErrInvalidTransactionExtra, err)
	}
	if limitReader.Left() > 0 {
		return errors.New("bytes leftover in extra data")
	}
	if c.ExtraBaseRCT, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if c.ExtraBaseRCT != 0 {
		return errors.New("invalid extra base RCT")
	}

	return nil
}

func (c *CoinbaseV2) FromReader(reader utils.ReaderAndByteReader, canBePruned, containsAuxiliaryTemplateId bool) (err error) {
	var version uint8

	if version, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if version != 2 {
		return errors.New("version not supported")
	}

	return c.FromVersionReader(reader, canBePruned, containsAuxiliaryTemplateId)
}

func (c *CoinbaseV2) MarshalBinary() ([]byte, error) {
	return c.MarshalBinaryFlags(false, false)
}

func (c *CoinbaseV2) PrunedBufferLength() int {
	return c.BufferLength()
}

func (c *CoinbaseV2) BufferLength() int {
	return 1 +
		utils.UVarInt64Size(c.UnlockTime) +
		1 + 1 +
		utils.UVarInt64Size(c.GenHeight) +
		c.MinerOutputs.BufferLength() +
		utils.UVarInt64Size(c.Extra.BufferLength()) + c.Extra.BufferLength() + 1
}

func (c *CoinbaseV2) MarshalBinaryFlags(pruned, containsAuxiliaryTemplateId bool) ([]byte, error) {
	return c.AppendBinaryFlags(make([]byte, 0, c.BufferLength()), pruned, containsAuxiliaryTemplateId)
}

func (c *CoinbaseV2) AppendPrunedBinary(preAllocatedBuf []byte) (data []byte, err error) {
	return c.AppendBinary(preAllocatedBuf)
}

func (c *CoinbaseV2) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	return c.AppendBinaryFlags(preAllocatedBuf, false, false)
}

func (c *CoinbaseV2) AppendBinaryFlags(preAllocatedBuf []byte, pruned, containsAuxiliaryTemplateId bool) ([]byte, error) {
	buf := preAllocatedBuf

	buf = append(buf, c.Version())
	buf = binary.AppendUvarint(buf, c.UnlockTime)
	buf = append(buf, c.InputCount, c.InputType)
	buf = binary.AppendUvarint(buf, c.GenHeight)

	extra := c.Extra

	if pruned {
		//pruned output
		buf = binary.AppendUvarint(buf, 0)
		buf = binary.AppendUvarint(buf, c.AuxiliaryData.TotalReward)
		buf = binary.AppendUvarint(buf, uint64(c.MinerOutputs.BufferLength()))

		if containsAuxiliaryTemplateId {
			buf = append(buf, c.AuxiliaryData.TemplateId[:]...)
		}

		if len(extra) > 0 && extra[len(extra)-1].Tag == TxExtraTagAdditionalPubKeys {
			// do not encode additional pubkeys!
			extra = extra[:len(extra)-1]
		}
	} else {
		buf, _ = c.MinerOutputs.AppendBinary(buf)
	}

	buf = binary.AppendUvarint(buf, uint64(extra.BufferLength()))
	buf, _ = extra.AppendBinary(buf)
	buf = append(buf, c.ExtraBaseRCT)

	return buf, nil
}

func (c *CoinbaseV2) OutputsBlob() ([]byte, error) {
	return c.MinerOutputs.MarshalBinary()
}

func (c *CoinbaseV2) SideChainHashingBlob(preAllocatedBuf []byte, majorVersion uint8, zeroTemplateId bool) ([]byte, error) {
	buf := preAllocatedBuf

	buf = append(buf, c.Version())
	buf = binary.AppendUvarint(buf, c.UnlockTime)
	buf = append(buf, c.InputCount, c.InputType)
	buf = binary.AppendUvarint(buf, c.GenHeight)

	buf, _ = c.MinerOutputs.AppendBinary(buf)

	buf = binary.AppendUvarint(buf, uint64(c.Extra.BufferLength()))
	buf, _ = c.Extra.SideChainHashingBlob(buf, majorVersion, zeroTemplateId)
	buf = append(buf, c.ExtraBaseRCT)

	return buf, nil
}

var baseRCTZeroHash = crypto.Keccak256([]byte{0})

func (c *CoinbaseV2) Hash() (hash types.Hash) {

	txBytes, _ := c.AppendBinaryFlags(make([]byte, 0, c.BufferLength()), false, false)

	hasher := crypto.NewKeccak256()

	// coinbase id, base RCT hash, prunable RCT hash
	var txHashingBlob [3 * types.HashSize]byte

	// remove base RCT
	_, _ = hasher.Write(txBytes[:len(txBytes)-1])
	_, _ = hasher.Read(txHashingBlob[:types.HashSize])

	if c.ExtraBaseRCT == 0 {
		// Base RCT, single 0 byte in miner tx
		copy(txHashingBlob[1*types.HashSize:], baseRCTZeroHash[:])
	} else {
		// fallback, but should never be hit
		hasher.Reset()
		_, _ = hasher.Write([]byte{c.ExtraBaseRCT})
		_, _ = hasher.Read(txHashingBlob[1*types.HashSize : 2*types.HashSize])
	}

	// Prunable RCT, empty in miner tx
	//copy(txHashingBlob[2*types.HashSize:], types.ZeroHash[:])

	hasher.Reset()
	_, _ = hasher.Write(txHashingBlob[:])
	hasher.Hash(&hash)

	return hash
}
