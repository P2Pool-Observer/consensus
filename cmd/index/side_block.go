package index

import (
	"bytes"
	"encoding/binary"
	"errors"
	"git.gammaspectra.live/P2Pool/p2pool-observer/monero/address"
	mainblock "git.gammaspectra.live/P2Pool/p2pool-observer/monero/block"
	"git.gammaspectra.live/P2Pool/p2pool-observer/p2pool/sidechain"
	p2pooltypes "git.gammaspectra.live/P2Pool/p2pool-observer/p2pool/types"
	"git.gammaspectra.live/P2Pool/p2pool-observer/types"
	"unsafe"
)

type BlockInclusion int

const (
	// InclusionOrphan orphan (was not included in-verified-chain)
	InclusionOrphan = BlockInclusion(iota)
	// InclusionInVerifiedChain in-verified-chain (uncle or main)
	InclusionInVerifiedChain
	// InclusionAlternateInVerifiedChain alternate in-verified-chain (uncle or main), for example when duplicate nonce happens
	InclusionAlternateInVerifiedChain

	InclusionCount
)

const SideBlockSelectFields = "main_id, main_height, template_id, side_height, parent_template_id, miner, uncle_of, effective_height, nonce, extra_nonce, timestamp, software_id, software_version, window_depth, window_outputs, transaction_count, difficulty, cumulative_difficulty, pow_difficulty, pow_hash, inclusion"

type SideBlock struct {
	// MainId mainchain id, on Monero network
	MainId     types.Hash `json:"main_id"`
	MainHeight uint64     `json:"main_height"`

	// TemplateId -- sidechain template id. Note multiple blocks can exist per template id, see Inclusion
	TemplateId types.Hash `json:"template_id"`
	SideHeight uint64     `json:"side_height"`
	// ParentTemplateId previous sidechain template id
	ParentTemplateId types.Hash `json:"parent_template_id"`

	// Miner internal id of the miner who contributed the block
	Miner uint64 `json:"miner_id"`

	// Uncle inclusion information

	// UncleOf has been included under this parent block TemplateId as an uncle
	UncleOf types.Hash `json:"uncle_of,omitempty"`
	// EffectiveHeight has been included under this parent block height as an uncle, or is this height
	EffectiveHeight uint64 `json:"effective_height"`

	// Nonce data
	Nonce      uint32 `json:"nonce"`
	ExtraNonce uint32 `json:"extra_nonce"`

	Timestamp       uint64                      `json:"timestamp"`
	SoftwareId      p2pooltypes.SoftwareId      `json:"software_id"`
	SoftwareVersion p2pooltypes.SoftwareVersion `json:"software_version"`
	// WindowDepth PPLNS window depth, in blocks including this one
	WindowDepth   uint32 `json:"window_depth"`
	WindowOutputs uint32 `json:"window_outputs"`

	// Difficulty sidechain difficulty at height
	Difficulty           uint64           `json:"difficulty"`
	CumulativeDifficulty types.Difficulty `json:"cumulative_difficulty"`
	PowDifficulty        uint64           `json:"pow_difficulty"`
	// PowHash result of PoW function as a hash (all 0x00 = not known)
	PowHash types.Hash `json:"pow_hash"`

	Inclusion BlockInclusion `json:"inclusion"`

	TransactionCount uint32 `json:"transaction_count"`

	// Extra information filled just for JSON purposes

	MinedMainAtHeight bool                  `json:"mined_main_at_height,omitempty"`
	MinerAddress      *address.Address      `json:"miner_address,omitempty"`
	MinerAlias        string                `json:"miner_alias,omitempty"`
	Uncles            []SideBlockUncleEntry `json:"uncles,omitempty"`
	MainDifficulty    uint64                `json:"main_difficulty,omitempty"`
}

type SideBlockUncleEntry struct {
	TemplateId types.Hash `json:"template_id"`
	Miner      uint64     `json:"miner_id"`
	SideHeight uint64     `json:"side_height"`
	Difficulty uint64     `json:"difficulty"`
}

// FromPoolBlock block needs to be pre-processed for ids to be correct
// These fields need to be filled by caller to match needs:
// SideBlock.UncleOf
// SideBlock.EffectiveHeight
// SideBlock.WindowDepth
// SideBlock.Inclusion
func (b *SideBlock) FromPoolBlock(i *Index, block *sidechain.PoolBlock, getSeedByHeight mainblock.GetSeedByHeightFunc) error {
	b.MainId = block.MainId()
	b.TemplateId = block.SideTemplateId(i.consensus)

	if b.MainId == types.ZeroHash {
		return errors.New("invalid main id")
	}
	if b.TemplateId == types.ZeroHash || bytes.Compare(b.TemplateId[:], block.CoinbaseExtra(sidechain.SideTemplateId)) != 0 {
		return errors.New("invalid template id")
	}
	b.MainHeight = block.Main.Coinbase.GenHeight
	b.SideHeight = block.Side.Height
	b.ParentTemplateId = block.Side.Parent
	b.Miner = i.GetOrCreateMinerPackedAddress(block.GetAddress()).id
	b.Nonce = block.Main.Nonce
	b.ExtraNonce = block.ExtraNonce()
	b.Timestamp = block.Main.Timestamp
	b.SoftwareId = block.Side.ExtraBuffer.SoftwareId
	b.SoftwareVersion = block.Side.ExtraBuffer.SoftwareVersion
	b.WindowOutputs = uint32(len(block.Main.Coinbase.Outputs))
	b.TransactionCount = uint32(len(block.Main.Transactions))
	b.Difficulty = block.Side.Difficulty.Lo
	b.CumulativeDifficulty = block.Side.CumulativeDifficulty
	b.PowHash = block.PowHash(i.Consensus().GetHasher(), getSeedByHeight)
	if b.PowHash == types.ZeroHash {
		return errors.New("invalid pow hash")
	}
	b.PowDifficulty = types.DifficultyFromPoW(b.PowHash).Lo

	return nil
}

func (b *SideBlock) SetUncleOf(block *SideBlock) error {
	if block == nil {
		b.UncleOf = types.ZeroHash
		b.EffectiveHeight = b.SideHeight
		return nil
	}
	if block.IsUncle() {
		return errors.New("parent cannot be uncle")
	}
	if block.SideHeight <= b.SideHeight {
		return errors.New("parent side height cannot be lower or equal")
	}
	b.UncleOf = block.TemplateId
	b.EffectiveHeight = block.EffectiveHeight
	return nil
}

// IsTipOfHeight whether this block is considered to be the "main" block within this height, not an uncle, or alternate
func (b *SideBlock) IsTipOfHeight() bool {
	return b.SideHeight == b.EffectiveHeight && b.Inclusion == InclusionInVerifiedChain
}

func (b *SideBlock) FullId() sidechain.FullId {
	var buf sidechain.FullId
	copy(buf[:], b.TemplateId[:])
	binary.LittleEndian.PutUint32(buf[types.HashSize:], b.Nonce)
	binary.LittleEndian.PutUint32(buf[types.HashSize+unsafe.Sizeof(b.Nonce):], b.ExtraNonce)
	return buf
}

func (b *SideBlock) IsUncle() bool {
	return b.SideHeight != b.EffectiveHeight && b.UncleOf != types.ZeroHash
}

func (b *SideBlock) IsOrphan() bool {
	return b.Inclusion == InclusionOrphan
}

func (b *SideBlock) ScanFromRow(i *Index, row RowScanInterface) error {
	if err := row.Scan(&b.MainId, &b.MainHeight, &b.TemplateId, &b.SideHeight, &b.ParentTemplateId, &b.Miner, &b.UncleOf, &b.EffectiveHeight, &b.Nonce, &b.ExtraNonce, &b.Timestamp, &b.SoftwareId, &b.SoftwareVersion, &b.WindowDepth, &b.WindowOutputs, &b.TransactionCount, &b.Difficulty, &b.CumulativeDifficulty, &b.PowDifficulty, &b.PowHash, &b.Inclusion); err != nil {
		return err
	}
	return nil
}

//Utilities to be used by JSON decoded blocks

func (b *SideBlock) Weight(tipHeight, windowSize, consensusUnclePenalty uint64) (weight, parentWeight uint64) {
	if (tipHeight - b.SideHeight) >= windowSize {
		return 0, 0
	}
	if b.IsUncle() {
		unclePenalty := types.DifficultyFrom64(b.Difficulty).Mul64(consensusUnclePenalty).Div64(100)
		uncleWeight := b.Difficulty - unclePenalty.Lo

		return uncleWeight, unclePenalty.Lo
	} else {
		weight = b.Difficulty
		for _, u := range b.Uncles {
			if (tipHeight - u.SideHeight) >= windowSize {
				continue
			}
			weight += types.DifficultyFrom64(u.Difficulty).Mul64(consensusUnclePenalty).Div64(100).Lo
		}
		return weight, 0
	}
}
