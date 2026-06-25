package block

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	fcmp_pp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// MaxTransactionCount TODO: this differs from P2Pool's num_transactions >= MAX_BLOCK_SIZE / HASH_SIZE)
const MaxTransactionCount = uint64(math.MaxUint64) / types.HashSize

type GenericBlock = Block[transaction.GenericCoinbase, *transaction.GenericCoinbase]
type PoolMainBlock = Block[transaction.P2PoolCoinbaseV2, *transaction.P2PoolCoinbaseV2]

// Block Main Monero block
// todo: cleanup types when https://github.com/golang/go/issues/61731 is in
type Block[T transaction.KnownMinerTransactions, MT transaction.TypedMinerTransaction[T]] struct {
	MajorVersion uint8 `json:"major_version"`
	MinorVersion uint8 `json:"minor_version"`
	// Nonce re-arranged here to improve memory layout space
	Nonce uint32 `json:"nonce"`

	Timestamp  uint64     `json:"timestamp"`
	PreviousId types.Hash `json:"previous_id"`
	//Nonce would be here

	Coinbase T `json:"coinbase"`

	Transactions []types.Hash `json:"transactions,omitempty"`
	// TransactionParentIndices amount of reward existing MinerOutputs. Used by p2pool serialized compact broadcasted blocks in protocol >= 1.1, filled only in compact blocks or by pre-processing.
	TransactionParentIndices []uint64 `json:"transaction_parent_indices,omitempty"`

	FCMPTreeLayers uint8      `json:"fcmp_pp_n_tree_layers,omitzero"`
	FCMPTreeRoot   types.Hash `json:"fcmp_pp_tree_root,omitzero"`
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

func (b *Block[T, MT]) MarshalBinary() (buf []byte, err error) {
	return b.MarshalBinaryFlags(false, false, false)
}

func (b *Block[T, MT]) BufferLength() int {
	size := utils.UVarInt64Size(b.MajorVersion) +
		utils.UVarInt64Size(b.MinorVersion) +
		utils.UVarInt64Size(b.Timestamp) +
		types.HashSize +
		4 + b.MinerTx().BufferLength() +
		utils.UVarInt64Size(len(b.Transactions)) + types.HashSize*len(b.Transactions)

	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		size += 1 + types.HashSize
	}
	return size
}

func (b *Block[T, MT]) MarshalBinaryFlags(compact, pruned, containsAuxiliaryTemplateId bool) (buf []byte, err error) {
	return b.AppendBinaryFlags(make([]byte, 0, b.BufferLength()), pruned, compact, containsAuxiliaryTemplateId)
}

func (b *Block[T, MT]) AppendBinaryFlags(preAllocatedBuf []byte, compact, pruned, containsAuxiliaryTemplateId bool) (buf []byte, err error) {
	buf = preAllocatedBuf

	if b.MajorVersion > monero.HardForkSupportedVersion || ((compact || pruned) && b.MajorVersion < monero.HardForkMinimumP2PoolSupportedVersion) {
		return nil, utils.ErrorfNoEscape("unsupported version %d", b.MajorVersion)
	}

	if b.MinorVersion < b.MajorVersion && !(b.MinorVersion == 0 && b.MajorVersion == 1) {
		return nil, utils.ErrorfNoEscape("minor version %d smaller than major %d", b.MinorVersion, b.MajorVersion)
	}

	if b.MajorVersion >= monero.HardForkRejectManyMinerOutputs {
		// TODO: check this on pruned?

		if len(b.MinerTx().Outputs()) > monero.MaxMinerOutputs {
			return nil, utils.ErrorfNoEscape("too many outputs: %d > %d", len(b.MinerTx().Outputs()), monero.MaxMinerOutputs)
		}
	}

	if b.MajorVersion >= monero.HardForkRejectLargeExtra {
		// TODO: check this on pruned?

		// Scale extra limit by number of outputs since Carrot requires 1 32-byte ephemeral pubkey per output (for Janus).
		maxExtraSize := monero.MaxTxExtraSize + len(b.MinerTx().Outputs())*monero.MinerTxExtraSizePerOutput
		if extra := b.MinerTx().ExtraTags(); extra.BufferLength() >= maxExtraSize || (extra == nil && len(b.MinerTx().ExtraData()) >= maxExtraSize) {
			return nil, utils.ErrorfNoEscape("too large tx extra: %d >= %d", extra.BufferLength(), maxExtraSize)
		}
	}

	buf = binary.AppendUvarint(buf, uint64(b.MajorVersion))
	buf = binary.AppendUvarint(buf, uint64(b.MinorVersion))

	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, b.Nonce)

	if buf, err = b.MinerTx().AppendBinaryFlags(buf, pruned, containsAuxiliaryTemplateId); err != nil {
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

func (b *Block[T, MT]) FromReader(reader utils.ReaderAndByteReader, canBePruned bool, f PrunedFlagsFunc) (err error) {
	return b.FromReaderFlags(reader, false, canBePruned, f)
}

func (b *Block[T, MT]) FromCompactReader(reader utils.ReaderAndByteReader, canBePruned bool, f PrunedFlagsFunc) (err error) {
	return b.FromReaderFlags(reader, true, canBePruned, f)
}

func (b *Block[T, MT]) UnmarshalBinary(data []byte, canBePruned bool, f PrunedFlagsFunc) error {
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

func (b *Block[T, MT]) FromReaderFlags(reader utils.ReaderAndByteReader, compact, canBePruned bool, f PrunedFlagsFunc) (err error) {
	var (
		txCount         uint64
		transactionHash types.Hash
	)

	if b.MajorVersion, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if b.MajorVersion > monero.HardForkSupportedVersion || ((compact || canBePruned) && b.MajorVersion < monero.HardForkMinimumP2PoolSupportedVersion) {
		return utils.ErrorfNoEscape("unsupported version %d", b.MajorVersion)
	}

	if b.MinorVersion, err = utils.ReadByteNoEscape(reader); err != nil {
		return err
	}

	if b.MinorVersion < b.MajorVersion && !(b.MinorVersion == 0 && b.MajorVersion == 1) {
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
	if err = b.MinerTx().FromReaderFlags(reader, canBePruned, containsAuxiliaryTemplateId); err != nil {
		return utils.ErrorfNoEscape("coinbase: %w", err)
	}

	if b.MajorVersion >= monero.HardForkRejectManyMinerOutputs {
		//TODO: check this on pruned p2pool blocks?

		if len(b.MinerTx().Outputs()) > monero.MaxMinerOutputs {
			return utils.ErrorfNoEscape("too many outputs: %d > %d", len(b.MinerTx().Outputs()), monero.MaxMinerOutputs)
		}
	}

	if b.MajorVersion >= monero.HardForkRejectLargeExtra {
		//TODO: check this on pruned p2pool blocks?

		// Scale extra limit by number of outputs since Carrot requires 1 32-byte ephemeral pubkey per output (for Janus).
		maxExtraSize := monero.MaxTxExtraSize + len(b.MinerTx().Outputs())*monero.MinerTxExtraSizePerOutput
		if extra := b.MinerTx().ExtraTags(); extra.BufferLength() >= maxExtraSize || (extra == nil && len(b.MinerTx().ExtraData()) >= maxExtraSize) {
			return utils.ErrorfNoEscape("too large tx extra: %d >= %d", extra.BufferLength(), maxExtraSize)
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
			// rough hard cap to p2pool cap
			const maxCompactTransactions = (128 * 1024) / types.HashSize
			if txCount > maxCompactTransactions {
				return utils.ErrorfNoEscape("compact transaction count too large: %d > %d", txCount, maxCompactTransactions)
			}

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

func (b *Block[T, MT]) Header() *Header {
	return &Header{
		MajorVersion: b.MajorVersion,
		MinorVersion: b.MinorVersion,
		Timestamp:    b.Timestamp,
		PreviousId:   b.PreviousId,
		Height:       b.MinerTx().GenHeight(),
		Nonce:        b.Nonce,
		Reward:       b.MinerTx().TotalReward(),
		Id:           b.Id(),
		Difficulty:   types.ZeroDifficulty,
	}
}

func (b *Block[T, MT]) HeaderBlobBufferLength() int {
	return 1 + 1 +
		utils.UVarInt64Size(b.Timestamp) +
		types.HashSize +
		4
}

func (b *Block[T, MT]) HeaderBlob(preAllocatedBuf []byte) []byte {
	buf := preAllocatedBuf
	buf = append(buf, b.MajorVersion, b.MinorVersion)
	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, b.Nonce)

	return buf
}

// SideChainHashingBlob Same as MarshalBinary but with nonce or template id set to 0
func (b *Block[T, MT]) SideChainHashingBlob(preAllocatedBuf []byte, zeroTemplateId bool) (buf []byte, err error) {
	minerTx, ok := any(&b.Coinbase).(*transaction.P2PoolCoinbaseV2)
	if !ok {
		return nil, utils.ErrorfNoEscape("unsupported coinbase")
	}

	buf = preAllocatedBuf
	buf = append(buf, b.MajorVersion, b.MinorVersion)
	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, 0) //replaced nonce

	if buf, err = minerTx.SideChainHashingBlob(buf, b.MajorVersion, zeroTemplateId); err != nil {
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

func (b *Block[T, MT]) HashingBlobBufferLength() int {
	return b.HeaderBlobBufferLength() +
		types.HashSize + utils.UVarInt64Size(len(b.Transactions)+1)
}

func (b *Block[T, MT]) HashingBlob(preAllocatedBuf []byte) []byte {
	buf := b.HeaderBlob(preAllocatedBuf)

	reserve := 1
	reserveOffset := 0
	if b.MajorVersion >= monero.HardForkFCMPPlusPlus {
		reserve += 2
	}

	merkleTree := make(crypto.MerkleTree, len(b.Transactions)+reserve)

	merkleTree[reserveOffset] = b.MinerTx().Hash()
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

func (b *Block[T, MT]) Difficulty(f GetDifficultyByHeightFunc) types.Difficulty {
	//cached by sidechain.Share
	return f(b.MinerTx().GenHeight())
}

var ErrNoSeed = errors.New("could not get seed")
var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

func (b *Block[T, MT]) powHashCN() (types.Hash, error) {
	blob := b.HashingBlob(make([]byte, 0, b.HashingBlobBufferLength()))
	var state cryptonight.State
	if b.MajorVersion < monero.HardForkCryptoNightV1 {
		return state.Sum(blob, cryptonight.V0, false), nil
	} else if b.MajorVersion < monero.HardForkCryptoNightV2 {
		return state.Sum(blob, cryptonight.V1, false), nil
	} else if b.MajorVersion < monero.HardForkCryptoNightR {
		return state.Sum(blob, cryptonight.V2, false), nil
	} else if b.MajorVersion < monero.HardForkRandomX {
		return state.SumR(blob, b.MinerTx().GenHeight(), false), nil
	} else {
		return types.ZeroHash, ErrUnsupportedAlgorithm
	}
}

func (b *Block[T, MT]) PowHashWithError(hasher randomx.Hasher, f GetSeedByHeightFunc) (types.Hash, error) {
	//not cached

	if b.MinerTx().GenHeight() == 202612 {
		// commit https://github.com/monero-project/monero/commit/c05489938f2735efe1539cfab77d28e4ef2baa48
		// introduced a bug where every block on this height produced the same PoW hash.
		// Specifically add mainnet/testnet/stressnet hashes to match, as by the time they reached that height the fix was in.
		// see upstream fix on https://github.com/monero-project/monero/pull/10801

		if slices.Contains(knownHashesBlock202612[:], b.Id()) {
			return powHashBlock202612, nil
		}
	}

	if b.MajorVersion < monero.HardForkRandomX {
		return b.powHashCN()
	}

	if seed := f(b.MinerTx().GenHeight()); seed == types.ZeroHash {
		return types.ZeroHash, ErrNoSeed
	} else {
		return hasher.Hash(seed[:], b.HashingBlob(make([]byte, 0, b.HashingBlobBufferLength())))
	}
}

var powHashBlock202612 = types.MustHashFromString("84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000")

var correctHashBlock202612 = types.MustHashFromString("426d16cff04c71f8b16340b722dc4010a2dd3831c22041431f772547ba6e331a")
var existingHashBlock202612 = types.MustHashFromString("bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698")

var knownHashesBlock202612 = [3]types.Hash{
	// mainnet
	existingHashBlock202612,
	// testnet
	types.MustHashFromString("248fde4b96b829c4ddbd00e3f76d35b03d01257898bc1b5578bc9e04b379a676"),
	// stagenet
	types.MustHashFromString("f3449e658b5f880c4b0e69007ed5d092c9c883ac3a518166fa652d5cc505e7b1"),
}

func (b *Block[T, MT]) Id() types.Hash {
	var varIntBuf [binary.MaxVarintLen64]byte
	buf := b.HashingBlob(make([]byte, 0, b.HashingBlobBufferLength()))
	h := crypto.Keccak256Var(varIntBuf[:binary.PutUvarint(varIntBuf[:], uint64(len(buf)))], buf)
	if b.MinerTx().GenHeight() == 202612 {
		if h == correctHashBlock202612 {
			return existingHashBlock202612
		} else if h == existingHashBlock202612 {
			// make sure that we aren't looking at a block with the 202612 block id but not the correct blobdata
			return types.ZeroHash
		}
	}
	return h
}

func (b *Block[T, MT]) MinerTx() MT {
	return MT(&b.Coinbase)
}
