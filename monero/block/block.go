package block

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	fcmp_pp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// MaxTransactionCount TODO: this differs from P2Pool's num_transactions >= MAX_BLOCK_SIZE / HASH_SIZE)
const MaxTransactionCount = uint64(math.MaxUint64) / types.HashSize

type Block struct {
	MajorVersion uint8 `json:"major_version"`
	MinorVersion uint8 `json:"minor_version"`
	// Nonce re-arranged here to improve memory layout space
	Nonce uint32 `json:"nonce"`

	Timestamp  uint64     `json:"timestamp"`
	PreviousId types.Hash `json:"previous_id"`
	//Nonce would be here

	Coinbase transaction.CoinbaseV2 `json:"coinbase"`

	Transactions []types.Hash `json:"transactions,omitempty"`
	// TransactionParentIndices amount of reward existing MinerOutputs. Used by p2pool serialized compact broadcasted blocks in protocol >= 1.1, filled only in compact blocks or by pre-processing.
	TransactionParentIndices []uint64 `json:"transaction_parent_indices,omitempty"`

	FCMPTreeLayers uint8      `json:"fcmp_pp_n_tree_layers,omitempty"`
	FCMPTreeRoot   types.Hash `json:"fcmp_pp_tree_root,omitempty"`
}

type Header struct {
	MajorVersion uint8 `json:"major_version"`
	MinorVersion uint8 `json:"minor_version"`
	// Nonce re-arranged here to improve memory layout space
	Nonce uint32 `json:"nonce"`

	Timestamp  uint64     `json:"timestamp"`
	PreviousId types.Hash `json:"previous_id"`
	Height     uint64     `json:"height"`
	//Nonce would be here
	Reward     uint64           `json:"reward"`
	Difficulty types.Difficulty `json:"difficulty"`
	Id         types.Hash       `json:"id"`
}

func (b *Block) MarshalBinary() (buf []byte, err error) {
	return b.MarshalBinaryFlags(false, false, false)
}

func (b *Block) BufferLength() int {
	size := utils.UVarInt64Size(b.MajorVersion) +
		utils.UVarInt64Size(b.MinorVersion) +
		utils.UVarInt64Size(b.Timestamp) +
		types.HashSize +
		4 +
		b.Coinbase.BufferLength() +
		utils.UVarInt64Size(len(b.Transactions)) + types.HashSize*len(b.Transactions)
	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		size += 1 + types.HashSize
	}
	return size
}

func (b *Block) MarshalBinaryFlags(compact, pruned, containsAuxiliaryTemplateId bool) (buf []byte, err error) {
	return b.AppendBinaryFlags(make([]byte, 0, b.BufferLength()), pruned, compact, containsAuxiliaryTemplateId)
}

func (b *Block) AppendBinaryFlags(preAllocatedBuf []byte, compact, pruned, containsAuxiliaryTemplateId bool) (buf []byte, err error) {
	buf = preAllocatedBuf

	if b.MajorVersion < monero.HardForkMinimumSupportedVersion || b.MajorVersion > monero.HardForkSupportedVersion {
		return nil, utils.ErrorfNoEscape("unsupported version %d", b.MajorVersion)
	}

	if b.MinorVersion < b.MajorVersion {
		return nil, utils.ErrorfNoEscape("minor version %d smaller than major %d", b.MinorVersion, b.MajorVersion)
	}

	if b.MajorVersion >= monero.HardForkRejectManyMinerOutputs {
		// TODO: check this on pruned?

		if len(b.Coinbase.MinerOutputs) > monero.MaxMinerOutputs {
			return nil, utils.ErrorfNoEscape("too many outputs: %d > %d", len(b.Coinbase.MinerOutputs), monero.MaxMinerOutputs)
		}
	}

	if b.MajorVersion >= monero.HardForkRejectLargeExtra {
		// TODO: check this on pruned?

		// Scale extra limit by number of outputs since Carrot requires 1 32-byte ephemeral pubkey per output (for Janus).
		maxExtraSize := monero.MaxTxExtraSize + len(b.Coinbase.MinerOutputs)*monero.MinerTxExtraSizePerOutput
		if b.Coinbase.Extra.BufferLength() >= maxExtraSize {
			return nil, utils.ErrorfNoEscape("too large tx extra: %d >= %d", b.Coinbase.Extra.BufferLength(), maxExtraSize)
		}
	}

	buf = binary.AppendUvarint(buf, uint64(b.MajorVersion))
	buf = binary.AppendUvarint(buf, uint64(b.MinorVersion))

	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, b.Nonce)

	if buf, err = b.Coinbase.AppendBinaryFlags(buf, pruned, containsAuxiliaryTemplateId); err != nil {
		return nil, err
	}

	buf = binary.AppendUvarint(buf, uint64(len(b.Transactions)))
	if compact {
		for i, txId := range b.Transactions {
			if i < len(b.TransactionParentIndices) && b.TransactionParentIndices[i] != 0 {
				buf = binary.AppendUvarint(buf, b.TransactionParentIndices[i])
			} else {
				buf = binary.AppendUvarint(buf, 0)
				buf = append(buf, txId[:]...)
			}
		}
	} else {
		for _, txId := range b.Transactions {
			buf = append(buf, txId[:]...)
		}
	}

	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		buf = append(buf, b.FCMPTreeLayers)
		buf = append(buf, b.FCMPTreeRoot[:]...)
	}

	return buf, nil
}

type PrunedFlagsFunc func() (containsAuxiliaryTemplateId bool)

func (b *Block) FromReader(reader utils.ReaderAndByteReader, canBePruned bool, f PrunedFlagsFunc) (err error) {
	return b.FromReaderFlags(reader, false, canBePruned, f)
}

func (b *Block) FromCompactReader(reader utils.ReaderAndByteReader, canBePruned bool, f PrunedFlagsFunc) (err error) {
	return b.FromReaderFlags(reader, true, canBePruned, f)
}

func (b *Block) UnmarshalBinary(data []byte, canBePruned bool, f PrunedFlagsFunc) error {
	reader := bytes.NewReader(data)
	err := b.FromReader(reader, canBePruned, f)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}

func (b *Block) FromReaderFlags(reader utils.ReaderAndByteReader, compact, canBePruned bool, f PrunedFlagsFunc) (err error) {
	var (
		txCount         uint64
		transactionHash types.Hash
	)

	if b.MajorVersion, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if b.MajorVersion < monero.HardForkMinimumSupportedVersion || b.MajorVersion > monero.HardForkSupportedVersion {
		return utils.ErrorfNoEscape("unsupported version %d", b.MajorVersion)
	}

	if b.MinorVersion, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if b.MinorVersion < b.MajorVersion {
		return utils.ErrorfNoEscape("minor version %d smaller than major version %d", b.MinorVersion, b.MajorVersion)
	}

	if b.MinorVersion > 127 {
		return utils.ErrorfNoEscape("minor version %d larger than maximum byte varint size", b.MinorVersion)
	}

	if b.Timestamp, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, b.PreviousId[:]); err != nil {
		return err
	}

	if err = utils.ReadLittleEndianInteger(reader, &b.Nonce); err != nil {
		return err
	}

	var containsAuxiliaryTemplateId bool

	if canBePruned && f != nil {
		containsAuxiliaryTemplateId = f()
	}

	// Coinbase Tx Decoding
	{
		if err = b.Coinbase.FromReader(reader, canBePruned, containsAuxiliaryTemplateId); err != nil {
			return err
		}

		if b.MajorVersion >= monero.HardForkRejectManyMinerOutputs {
			// TODO: check this on pruned?

			if len(b.Coinbase.MinerOutputs) > monero.MaxMinerOutputs {
				return utils.ErrorfNoEscape("too many outputs: %d > %d", len(b.Coinbase.MinerOutputs), monero.MaxMinerOutputs)
			}
		}

		if b.MajorVersion >= monero.HardForkRejectLargeExtra {
			// TODO: check this on pruned?

			// Scale extra limit by number of outputs since Carrot requires 1 32-byte ephemeral pubkey per output (for Janus).
			maxExtraSize := monero.MaxTxExtraSize + len(b.Coinbase.MinerOutputs)*monero.MinerTxExtraSizePerOutput
			if b.Coinbase.Extra.BufferLength() >= maxExtraSize {
				return utils.ErrorfNoEscape("too large tx extra: %d >= %d", b.Coinbase.Extra.BufferLength(), maxExtraSize)
			}
		}
	}

	//TODO: verify hardfork major versions

	if txCount, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	} else if txCount > MaxTransactionCount {
		//TODO: #define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
		return utils.ErrorfNoEscape("transaction count too large: %d > %d", txCount, MaxTransactionCount)
	} else if txCount > 0 {
		if compact {
			// preallocate with soft cap
			b.Transactions = make([]types.Hash, 0, min(8192, txCount))
			b.TransactionParentIndices = make([]uint64, 0, min(8192, txCount))

			var parentIndex uint64
			for range txCount {
				if parentIndex, err = utils.ReadCanonicalUvarint(reader); err != nil {
					return err
				}

				if parentIndex == 0 {
					//not in lookup
					if _, err = utils.ReadFullNoEscape(reader, transactionHash[:]); err != nil {
						return err
					}

					b.Transactions = append(b.Transactions, transactionHash)
				} else {
					b.Transactions = append(b.Transactions, types.ZeroHash)
				}

				b.TransactionParentIndices = append(b.TransactionParentIndices, parentIndex)
			}
		} else {
			// preallocate with soft cap
			b.Transactions = make([]types.Hash, 0, min(8192, txCount))

			for range txCount {
				if _, err = utils.ReadFullNoEscape(reader, transactionHash[:]); err != nil {
					return err
				}
				b.Transactions = append(b.Transactions, transactionHash)
			}
		}
	}

	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		if b.FCMPTreeLayers, err = utils.ReadByteNoEscape(reader); err != nil {
			return err
		}
		if b.FCMPTreeLayers > fcmp_pp.MaxLayers {
			return utils.ErrorfNoEscape("layer count for FCMP++ too large: %d > %d", b.FCMPTreeLayers, fcmp_pp.MaxLayers)
		}
		if _, err = utils.ReadFullNoEscape(reader, b.FCMPTreeRoot[:]); err != nil {
			return err
		}
	}

	return nil
}

func (b *Block) Header() *Header {
	return &Header{
		MajorVersion: b.MajorVersion,
		MinorVersion: b.MinorVersion,
		Timestamp:    b.Timestamp,
		PreviousId:   b.PreviousId,
		Height:       b.Coinbase.GenHeight,
		Nonce:        b.Nonce,
		Reward:       b.Coinbase.AuxiliaryData.TotalReward,
		Id:           b.Id(),
		Difficulty:   types.ZeroDifficulty,
	}
}

func (b *Block) HeaderBlobBufferLength() int {
	return 1 + 1 +
		utils.UVarInt64Size(b.Timestamp) +
		types.HashSize +
		4
}

func (b *Block) HeaderBlob(preAllocatedBuf []byte) []byte {
	buf := preAllocatedBuf
	buf = append(buf, b.MajorVersion)
	buf = append(buf, b.MinorVersion)
	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, b.Nonce)

	return buf
}

// SideChainHashingBlob Same as MarshalBinary but with nonce or template id set to 0
func (b *Block) SideChainHashingBlob(preAllocatedBuf []byte, zeroTemplateId bool) (buf []byte, err error) {
	buf = preAllocatedBuf
	buf = append(buf, b.MajorVersion)
	buf = append(buf, b.MinorVersion)
	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, 0) //replaced nonce

	if buf, err = b.Coinbase.SideChainHashingBlob(buf, b.MajorVersion, zeroTemplateId); err != nil {
		return nil, err
	}

	buf = binary.AppendUvarint(buf, uint64(len(b.Transactions)))
	for _, txId := range b.Transactions {
		buf = append(buf, txId[:]...)
	}

	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		buf = append(buf, b.FCMPTreeLayers)
		buf = append(buf, b.FCMPTreeRoot[:]...)
	}

	return buf, nil
}

func (b *Block) HashingBlobBufferLength() int {
	return b.HeaderBlobBufferLength() +
		types.HashSize + utils.UVarInt64Size(len(b.Transactions)+1)
}

func (b *Block) HashingBlob(preAllocatedBuf []byte) []byte {
	buf := b.HeaderBlob(preAllocatedBuf)

	reserve := 1
	reserveOffset := 0
	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		reserve += 2
	}

	merkleTree := make(crypto.MerkleTree, len(b.Transactions)+reserve)

	merkleTree[reserveOffset] = b.Coinbase.Hash()
	reserveOffset++

	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		merkleTree[reserveOffset][0] = b.FCMPTreeLayers
		reserveOffset++
		merkleTree[reserveOffset] = b.FCMPTreeRoot
		reserveOffset++
	}

	copy(merkleTree[reserveOffset:], b.Transactions)
	txTreeHash := merkleTree.RootHash()
	buf = append(buf, txTreeHash[:]...)

	buf = binary.AppendUvarint(buf, uint64(len(b.Transactions)+1))

	return buf
}

func (b *Block) Difficulty(f GetDifficultyByHeightFunc) types.Difficulty {
	//cached by sidechain.Share
	return f(b.Coinbase.GenHeight)
}

var ErrNoSeed = errors.New("could not get seed")

func (b *Block) PowHashWithError(hasher randomx.Hasher, f GetSeedByHeightFunc) (types.Hash, error) {
	//not cached
	if seed := f(b.Coinbase.GenHeight); seed == types.ZeroHash {
		return types.ZeroHash, ErrNoSeed
	} else {
		return hasher.Hash(seed[:], b.HashingBlob(make([]byte, 0, b.HashingBlobBufferLength())))
	}
}

func (b *Block) Id() types.Hash {
	//cached by sidechain.Share
	var varIntBuf [binary.MaxVarintLen64]byte
	buf := b.HashingBlob(make([]byte, 0, b.HashingBlobBufferLength()))
	return crypto.Keccak256Var(varIntBuf[:binary.PutUvarint(varIntBuf[:], uint64(len(buf)))], buf)
}
