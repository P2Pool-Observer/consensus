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

type GenericCoinbase struct {
	version uint8

	// UnlockTime would be here
	InputCount uint8 `json:"input_count"`
	InputType  uint8 `json:"input_type"`
	// UnlockTime re-arranged here to improve memory layout space
	UnlockTime   uint64  `json:"unlock_time"`
	GenHeight    uint64  `json:"gen_height"`
	MinerOutputs Outputs `json:"vout"`

	Extra types.Bytes `json:"extra"`

	ExtraBaseRCT uint8 `json:"extra_base_rct,omitempty"`
}

func (c *GenericCoinbase) Version() uint8 {
	return c.version
}

func (c *GenericCoinbase) PrefixHash() types.Hash {
	prefixBytes, _ := c.AppendBinary(make([]byte, 0, c.BufferLength()))
	return crypto.Keccak256(prefixBytes[:len(prefixBytes)-1])
}

func (c *GenericCoinbase) Fee() uint64 {
	return 0
}

func (c *GenericCoinbase) Inputs() Inputs {
	return nil
}

func (c *GenericCoinbase) Outputs() Outputs {
	return c.MinerOutputs
}

func (c *GenericCoinbase) Proofs() Proofs {
	return nil
}

func (c *GenericCoinbase) PrunedBufferLength() int {
	return c.BufferLength()
}

func (c *GenericCoinbase) AppendPrunedBinary(preAllocatedBuf []byte) (data []byte, err error) {
	return c.AppendBinary(preAllocatedBuf)
}

// ExtraTags Returns a transaction extra decoded. This can err on corrupt blocks
func (c *GenericCoinbase) ExtraTags() ExtraTags {
	var tags ExtraTags
	err := tags.UnmarshalBinary(c.Extra)
	if err != nil {
		return nil
	}
	return tags
}

func (c *GenericCoinbase) TotalReward() (reward uint64) {
	for _, o := range c.MinerOutputs {
		reward += o.Amount
	}
	return reward
}

func (c *GenericCoinbase) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	err := c.FromReader(reader)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}

func (c *GenericCoinbase) FromReader(reader utils.ReaderAndByteReader) (err error) {
	var (
		txExtraSize uint64
	)

	if c.version, err = reader.ReadByte(); err != nil {
		return err
	}

	if c.version != 1 && c.version != 2 {
		return errors.New("version not supported")
	}

	if c.UnlockTime, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if c.InputCount, err = reader.ReadByte(); err != nil {
		return err
	}

	if c.InputCount != 1 {
		return errors.New("invalid input count")
	}

	if c.InputType, err = reader.ReadByte(); err != nil {
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
	}

	if txExtraSize, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	limitReader := utils.LimitByteReader(reader, int64(txExtraSize))

	_, err = utils.ReadFullProgressive(limitReader, &c.Extra, int(txExtraSize))
	if err != nil {
		return err
	}

	if limitReader.Left() > 0 {
		return errors.New("bytes leftover in extra data")
	}

	if c.version == 2 {

		if c.ExtraBaseRCT, err = reader.ReadByte(); err != nil {
			return err
		}

		if c.ExtraBaseRCT != 0 {
			return errors.New("invalid extra base RCT")
		}
	}

	return nil
}

func (c *GenericCoinbase) Weight() int {
	return c.BufferLength()
}

func (c *GenericCoinbase) BufferLength() int {
	n := 1 +
		utils.UVarInt64Size(c.UnlockTime) +
		1 + 1 +
		utils.UVarInt64Size(c.GenHeight) +
		c.MinerOutputs.BufferLength() +
		utils.UVarInt64Size(len(c.Extra)) + len(c.Extra)
	if c.version == 2 {
		n++
	}
	return n
}

func (c *GenericCoinbase) MarshalBinary() ([]byte, error) {
	return c.AppendBinary(make([]byte, 0, c.BufferLength()))
}

func (c *GenericCoinbase) AppendBinary(preAllocatedBuf []byte) ([]byte, error) {
	buf := preAllocatedBuf

	buf = append(buf, c.version)
	buf = binary.AppendUvarint(buf, c.UnlockTime)
	buf = append(buf, c.InputCount)
	buf = append(buf, c.InputType)
	buf = binary.AppendUvarint(buf, c.GenHeight)

	buf, _ = c.MinerOutputs.AppendBinary(buf)

	buf = binary.AppendUvarint(buf, uint64(len(c.Extra)))
	buf = append(buf, c.Extra...)

	if c.version == 2 {
		buf = append(buf, c.ExtraBaseRCT)
	}

	return buf, nil
}

func (c *GenericCoinbase) OutputsBlob() ([]byte, error) {
	return c.MinerOutputs.MarshalBinary()
}

func (c *GenericCoinbase) SignatureHash() types.Hash {
	return c.Hash()
}

func (c *GenericCoinbase) Hash() (hash types.Hash) {
	txBytes, _ := c.AppendBinary(make([]byte, 0, c.BufferLength()))
	if c.version == 1 {
		return crypto.Keccak256(txBytes)
	}

	hasher := crypto.NewKeccak256()

	// coinbase id, base RCT hash, prunable RCT hash
	var txHashingBlob [3 * types.HashSize]byte

	// remove base RCT
	_, _ = hasher.Write(txBytes[:len(txBytes)-1])
	_, _ = hasher.Read(txHashingBlob[:types.HashSize])

	if c.ExtraBaseRCT == 0 {
		// Base RCT, single 0 byte in miner tx
		copy(txHashingBlob[types.HashSize:2*types.HashSize], baseRCTZeroHash[:])
	} else {
		// fallback, but should never be hit
		hasher.Reset()
		_, _ = hasher.Write([]byte{c.ExtraBaseRCT})
		_, _ = hasher.Read(txHashingBlob[types.HashSize : 2*types.HashSize])
	}

	hasher.Reset()
	_, _ = hasher.Write(txHashingBlob[:])
	_, _ = hasher.Read(hash[:])

	return hash
}
