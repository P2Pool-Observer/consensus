package sidechain

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"git.gammaspectra.live/P2Pool/consensus/v3/merge_mining"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero"
	mainblock "git.gammaspectra.live/P2Pool/consensus/v3/monero/block"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/transaction"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v3/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/utils"
	"git.gammaspectra.live/P2Pool/sha3"
	"github.com/dolthub/swiss"
	"io"
	unsafeRandom "math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type Cache interface {
	GetBlob(key []byte) (blob []byte, err error)
	SetBlob(key, blob []byte) (err error)
	RemoveBlob(key []byte) (err error)
}

type P2PoolInterface interface {
	ConsensusProvider
	Cache
	Context() context.Context
	UpdateTip(tip *PoolBlock)
	Broadcast(block *PoolBlock)
	ClientRPC() *client.Client
	GetChainMainByHeight(height uint64) *ChainMain
	GetChainMainByHash(hash types.Hash) *ChainMain
	GetMinimalBlockHeaderByHeight(height uint64) *mainblock.Header
	GetMinimalBlockHeaderByHash(hash types.Hash) *mainblock.Header
	GetDifficultyByHeight(height uint64) types.Difficulty
	UpdateBlockFound(data *ChainMain, block *PoolBlock)
	SubmitBlock(block *mainblock.Block)
	GetChainMainTip() *ChainMain
	GetMinerDataTip() *p2pooltypes.MinerData
	Store(block *PoolBlock)
	ClearCachedBlocks()
}

type ChainMain struct {
	Difficulty types.Difficulty
	Height     uint64
	Timestamp  uint64
	Reward     uint64
	Id         types.Hash
}

type SideChain struct {
	derivationCache *DerivationCache
	server          P2PoolInterface

	seenBlocksLock sync.Mutex
	seenBlocks     *swiss.Map[FullId, struct{}]

	sidechainLock sync.RWMutex

	watchBlock           *ChainMain
	watchBlockPossibleId types.Hash

	blocksByTemplateId       *swiss.Map[types.Hash, *PoolBlock]
	blocksByMerkleRoot       *swiss.Map[types.Hash, *PoolBlock]
	blocksByHeight           *swiss.Map[uint64, []*PoolBlock]
	blocksByHeightKeysSorted bool
	blocksByHeightKeys       []uint64

	preAllocatedBuffer []byte

	syncTip           atomic.Pointer[PoolBlock]
	chainTip          atomic.Pointer[PoolBlock]
	currentDifficulty atomic.Pointer[types.Difficulty]

	precalcFinished atomic.Bool

	preAllocatedShares         Shares
	preAllocatedRewards        []uint64
	preAllocatedSharesPool     *PreAllocatedSharesPool
	preAllocatedDifficultyData []DifficultyData
	preAllocatedTimestampData  []uint64
	preAllocatedMinedBlocks    []types.Hash
}

func NewSideChain(server P2PoolInterface) *SideChain {
	s := &SideChain{
		derivationCache:            NewDerivationMapCache(),
		server:                     server,
		blocksByTemplateId:         swiss.NewMap[types.Hash, *PoolBlock](uint32(server.Consensus().ChainWindowSize*2 + 300)),
		blocksByHeight:             swiss.NewMap[uint64, []*PoolBlock](uint32(server.Consensus().ChainWindowSize*2 + 300)),
		preAllocatedShares:         PreAllocateShares(server.Consensus().ChainWindowSize * 2),
		preAllocatedRewards:        make([]uint64, 0, server.Consensus().ChainWindowSize*2),
		preAllocatedDifficultyData: make([]DifficultyData, 0, server.Consensus().ChainWindowSize*2),
		preAllocatedTimestampData:  make([]uint64, 0, server.Consensus().ChainWindowSize*2),
		preAllocatedSharesPool:     NewPreAllocatedSharesPool(server.Consensus().ChainWindowSize * 2),
		preAllocatedBuffer:         make([]byte, 0, PoolBlockMaxTemplateSize),
		preAllocatedMinedBlocks:    make([]types.Hash, 0, 6*UncleBlockDepth*2+1),
		seenBlocks:                 swiss.NewMap[FullId, struct{}](uint32(server.Consensus().ChainWindowSize*2 + 300)),
	}
	minDiff := types.DifficultyFrom64(server.Consensus().MinimumDifficulty)
	s.currentDifficulty.Store(&minDiff)
	return s
}

func (c *SideChain) Consensus() *Consensus {
	return c.server.Consensus()
}

func (c *SideChain) DerivationCache() *DerivationCache {
	return c.derivationCache
}

func (c *SideChain) Difficulty() types.Difficulty {
	return *c.currentDifficulty.Load()
}

func (c *SideChain) PreCalcFinished() bool {
	return c.precalcFinished.Load()
}

func (c *SideChain) PreprocessBlock(block *PoolBlock) (missingBlocks []types.Hash, err error) {
	var preAllocatedShares Shares
	if len(block.Main.Coinbase.Outputs) == 0 {
		//cannot use SideTemplateId() as it might not be proper to calculate yet. fetch appropriate identifier from coinbase only here
		if b := c.GetPoolBlockByTemplateId(block.FastSideTemplateId(c.Consensus())); b != nil {
			block.Main.Coinbase.Outputs = b.Main.Coinbase.Outputs
		} else {
			preAllocatedShares = c.preAllocatedSharesPool.Get()
			defer c.preAllocatedSharesPool.Put(preAllocatedShares)
		}
	}

	return block.PreProcessBlock(c.Consensus(), c.derivationCache, preAllocatedShares, c.server.GetDifficultyByHeight, c.GetPoolBlockByTemplateId)
}

func (c *SideChain) isWatched(block *PoolBlock) bool {
	if block.ShareVersion() > ShareVersion_V2 {
		return c.watchBlockPossibleId == block.MergeMiningTag().RootHash
	} else {
		return c.watchBlockPossibleId == block.FastSideTemplateId(c.Consensus())
	}
}

func (c *SideChain) fillPoolBlockTransactionParentIndices(block *PoolBlock) {
	block.FillTransactionParentIndices(c.Consensus(), c.getParent(block))
}

func (c *SideChain) isPoolBlockTransactionKeyIsDeterministic(block *PoolBlock) bool {
	kP := c.derivationCache.GetDeterministicTransactionKey(block.GetPrivateKeySeed(), block.Main.PreviousId)
	return bytes.Compare(block.CoinbaseExtra(SideCoinbasePublicKey), kP.PublicKey.AsSlice()) == 0 && block.Side.CoinbasePrivateKey == kP.PrivateKey.AsBytes()
}

func (c *SideChain) getSeedByHeightFunc() mainblock.GetSeedByHeightFunc {
	//TODO: do not make this return a function
	return func(height uint64) (hash types.Hash) {
		seedHeight := randomx.SeedHeight(height)
		if h := c.server.GetMinimalBlockHeaderByHeight(seedHeight); h != nil {
			return h.Id
		} else {
			return types.ZeroHash
		}
	}
}

func (c *SideChain) GetPossibleUncles(tip *PoolBlock, forHeight uint64) (uncles []types.Hash) {
	minedBlocks := make([]types.Hash, 0, UncleBlockDepth*2+1)
	tmp := tip
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	for i, n := uint64(0), min(UncleBlockDepth, tip.Side.Height+1); tmp != nil && (i < n); i++ {
		minedBlocks = append(minedBlocks, tmp.SideTemplateId(c.Consensus()))
		for _, uncleId := range tmp.Side.Uncles {
			minedBlocks = append(minedBlocks, uncleId)
		}
		tmp = c.getParent(tmp)
	}

	for i, n := uint64(0), min(UncleBlockDepth, tip.Side.Height+1); i < n; i++ {
		for _, uncle := range c.getPoolBlocksByHeight(tip.Side.Height - i) {
			// Only add verified and valid blocks
			if !uncle.Verified.Load() || uncle.Invalid.Load() {
				continue
			}

			// Only add it if it hasn't been mined already
			if slices.Contains(minedBlocks, uncle.SideTemplateId(c.Consensus())) {
				continue
			}

			if sameChain := func() bool {
				tmp = tip
				for tmp != nil && tmp.Side.Height > uncle.Side.Height {
					tmp = c.getParent(tmp)
				}
				if tmp == nil || tmp.Side.Height < uncle.Side.Height {
					return false
				}
				tmp2 := uncle
				for j := 0; j < UncleBlockDepth && tmp != nil && tmp2 != nil && (tmp.Side.Height+UncleBlockDepth >= forHeight); j++ {
					if tmp.Side.Parent == tmp2.Side.Parent {
						return true
					}
					tmp = c.getParent(tmp)
					tmp2 = c.getParent(tmp2)
				}
				return false
			}(); sameChain {
				uncles = append(uncles, uncle.SideTemplateId(c.Consensus()))
			}
		}
	}

	if len(uncles) > 0 {
		// Sort hashes, consensus
		slices.SortFunc(uncles, func(a, b types.Hash) int {
			return a.Compare(b)
		})
	}

	return uncles
}

func (c *SideChain) BlockSeen(block *PoolBlock) bool {
	tip := c.GetChainTip()

	//early exit for
	if tip != nil && tip.Side.Height > (block.Side.Height+c.Consensus().ChainWindowSize*2) && block.Side.CumulativeDifficulty.Cmp(tip.Side.CumulativeDifficulty) < 0 {
		return true
	}

	fullId := block.FullId(c.Consensus())

	c.seenBlocksLock.Lock()
	defer c.seenBlocksLock.Unlock()
	if c.seenBlocks.Has(fullId) {
		return true
	} else {
		c.seenBlocks.Put(fullId, struct{}{})
		return false
	}
}

func (c *SideChain) BlockUnsee(block *PoolBlock) {
	fullId := block.FullId(c.Consensus())

	c.seenBlocksLock.Lock()
	defer c.seenBlocksLock.Unlock()
	c.seenBlocks.Delete(fullId)
}

func (c *SideChain) PoolBlockExternalVerify(block *PoolBlock) (missingBlocks []types.Hash, err error, ban bool) {
	defer func() {
		if e := recover(); e != nil {
			//recover from panics
			missingBlocks = nil
			if panicError, ok := e.(error); ok {
				err = fmt.Errorf("panic: %w", panicError)
			} else {
				err = fmt.Errorf("panic: %v", e)
			}
			ban = true
			utils.Errorf("SideChain", "external_block_verify: panic %v, block %+v", e, block)
		}
	}()

	// Technically some p2pool node could keep stuffing block with transactions until reward is less than 0.6 XMR
	// But default transaction picking algorithm never does that. It's better to just ban such nodes
	if block.Main.Coinbase.AuxiliaryData.TotalReward < monero.TailEmissionReward {
		return nil, errors.New("block reward too low"), true
	}

	// Enforce deterministic tx keys starting from v15
	if block.Main.MajorVersion >= monero.HardForkViewTagsVersion {
		if !c.isPoolBlockTransactionKeyIsDeterministic(block) {
			return nil, errors.New("invalid deterministic transaction keys"), true
		}
	}

	// Both tx types are allowed by Monero consensus during v15 because it needs to process pre-fork mempool transactions,
	// but P2Pool can switch to using only TXOUT_TO_TAGGED_KEY for miner payouts starting from v15
	expectedTxType := block.GetTransactionOutputType()

	if missingBlocks, err = c.PreprocessBlock(block); err != nil {
		return missingBlocks, err, true
	}
	for _, o := range block.Main.Coinbase.Outputs {
		if o.Type != expectedTxType {
			return nil, errors.New("unexpected transaction type"), true
		}
	}

	templateId := block.SideTemplateId(c.Consensus())

	if block.ShareVersion() > ShareVersion_V2 {
		if templateId != block.FastSideTemplateId(c.Consensus()) {
			return nil, fmt.Errorf("invalid template id %s, expected %s", block.FastSideTemplateId(c.Consensus()), templateId), true
		}

		//verify template id against merkle proof
		mmTag := block.MergeMiningTag()
		auxiliarySlot := merge_mining.GetAuxiliarySlot(c.Consensus().Id, mmTag.Nonce, mmTag.NumberAuxiliaryChains)

		if !block.Side.MerkleProof.Verify(templateId, int(auxiliarySlot), int(mmTag.NumberAuxiliaryChains), mmTag.RootHash) {
			return nil, fmt.Errorf("could not verify template id %s merkle proof against merkle tree root hash %s (number of chains = %d, nonce = %d, auxiliary slot = %d)", templateId, mmTag.RootHash, mmTag.NumberAuxiliaryChains, mmTag.Nonce, auxiliarySlot), true
		}
	} else {
		if templateId != types.HashFromBytes(block.CoinbaseExtra(SideIdentifierHash)) {
			return nil, fmt.Errorf("invalid template id %s, expected %s", block.SideTemplateId(c.Consensus()), templateId), true
		}
	}

	if block.Side.Difficulty.Cmp64(c.Consensus().MinimumDifficulty) < 0 {
		return nil, fmt.Errorf("block mined by %s has invalid difficulty %s, expected >= %d", block.GetAddress().ToBase58(c.Consensus().NetworkType.AddressNetwork()), block.Side.Difficulty.StringNumeric(), c.Consensus().MinimumDifficulty), true
	}

	expectedDifficulty := c.Difficulty()
	tooLowDiff := block.Side.Difficulty.Cmp(expectedDifficulty) < 0

	if otherBlock := c.GetPoolBlockByTemplateId(templateId); otherBlock != nil {
		//already added
		newMainId := block.MainId()
		oldMainId := block.MainId()
		utils.Logf("SideChain", "add_external_block: block id = %s is already added. New main id = %s, old main id = %s", templateId, newMainId, oldMainId)
		if newMainId != oldMainId && otherBlock.Verified.Load() && !otherBlock.Invalid.Load() {
			//other sections have been verified already, check PoW for new Main blocks

			//specifically check Main id for nonce changes! p2pool does not do this

			if _, err := block.PowHashWithError(c.Consensus().GetHasher(), c.getSeedByHeightFunc()); err != nil {
				return nil, err, false
			} else {
				if isHigherMainChain, err := block.IsProofHigherThanMainDifficultyWithError(c.Consensus().GetHasher(), c.server.GetDifficultyByHeight, c.getSeedByHeightFunc()); err != nil {
					utils.Logf("SideChain", "add_external_block: couldn't get mainchain difficulty for height = %d: %s", block.Main.Coinbase.GenHeight, err)
				} else if isHigherMainChain {
					utils.Logf("SideChain", "add_external_block: ALTERNATE block %s has enough PoW for Monero height %d, submitting it", templateId.String(), block.Main.Coinbase.GenHeight)
					c.server.SubmitBlock(&block.Main)
				}
				if isHigher, err := block.IsProofHigherThanDifficultyWithError(c.Consensus().GetHasher(), c.getSeedByHeightFunc()); err != nil {
					return nil, err, true
				} else if !isHigher {
					return nil, fmt.Errorf("not enough PoW for id %s, height = %d, mainchain height %d", templateId.String(), block.Side.Height, block.Main.Coinbase.GenHeight), true
				}

				{
					c.sidechainLock.Lock()
					defer c.sidechainLock.Unlock()

					utils.Logf("SideChain", "add_external_block: ALTERNATE height = %d, id = %s, mainchain height = %d, verified = %t, total = %d", block.Side.Height, block.SideTemplateId(c.Consensus()), block.Main.Coinbase.GenHeight, block.Verified.Load(), c.blocksByTemplateId.Count())

					block.Verified.Store(true)
					block.Invalid.Store(false)
					if c.isWatched(block) {
						c.server.UpdateBlockFound(c.watchBlock, block)
						c.watchBlockPossibleId = types.ZeroHash
					}

					block.Depth.Store(otherBlock.Depth.Load())
					if block.WantBroadcast.Load() && !block.Broadcasted.Swap(true) {
						//re-broadcast alternate blocks
						c.server.Broadcast(block)
					}
					c.server.Store(block)
				}
			}
		}
		return nil, nil, false
	}

	// This is mainly an anti-spam measure, not an actual verification step
	if tooLowDiff {
		// Reduce required diff by 50% (by doubling this block's diff) to account for alternative chains
		diff2 := block.Side.Difficulty.Mul64(2)
		tip := c.GetChainTip()
		for tmp := tip; tmp != nil && (tmp.Side.Height+c.Consensus().ChainWindowSize > tip.Side.Height); tmp = c.GetParent(tmp) {
			if diff2.Cmp(tmp.Side.Difficulty) >= 0 {
				tooLowDiff = false
				break
			}
		}
	}

	if tooLowDiff {
		return nil, fmt.Errorf("block mined by %s has too low difficulty %s, expected >= %s", block.GetAddress().ToBase58(c.Consensus().NetworkType.AddressNetwork()), block.Side.Difficulty.StringNumeric(), expectedDifficulty.StringNumeric()), false
	}

	// This check is not always possible to perform because of mainchain reorgs
	if data := c.server.GetChainMainByHash(block.Main.PreviousId); data != nil {
		if (data.Height + 1) != block.Main.Coinbase.GenHeight {
			return nil, fmt.Errorf("wrong mainchain height %d, expected %d", block.Main.Coinbase.GenHeight, data.Height+1), true
		}
	} else {
		//TODO warn unknown block, reorg
	}

	return func() []types.Hash {
		c.sidechainLock.RLock()
		defer c.sidechainLock.RUnlock()
		missing := make([]types.Hash, 0, 4)
		if block.Side.Parent != types.ZeroHash && c.getPoolBlockByTemplateId(block.Side.Parent) == nil {
			missing = append(missing, block.Side.Parent)
		}

		for _, uncleId := range block.Side.Uncles {
			if uncleId != types.ZeroHash && c.getPoolBlockByTemplateId(uncleId) == nil {
				missing = append(missing, uncleId)
			}
		}
		return missing
	}(), nil, false
}

func (c *SideChain) AddPoolBlockExternal(block *PoolBlock) (missingBlocks []types.Hash, err error, ban bool) {
	defer func() {
		if e := recover(); e != nil {
			//recover from panics
			missingBlocks = nil
			if panicError, ok := e.(error); ok {
				err = fmt.Errorf("panic: %w", panicError)
			} else {
				err = fmt.Errorf("panic: %v", e)
			}
			ban = true
			utils.Errorf("SideChain", "add_external_block: panic %v, block %+v", e, block)
		}
	}()

	missingBlocks, err, ban = c.PoolBlockExternalVerify(block)
	if err != nil || ban {
		return
	}

	templateId := block.SideTemplateId(c.Consensus())

	if _, err := block.PowHashWithError(c.Consensus().GetHasher(), c.getSeedByHeightFunc()); err != nil {
		c.BlockUnsee(block)
		return nil, err, false
	} else {
		if isHigherMainChain, err := block.IsProofHigherThanMainDifficultyWithError(c.Consensus().GetHasher(), c.server.GetDifficultyByHeight, c.getSeedByHeightFunc()); err != nil {
			utils.Logf("SideChain", "add_external_block: couldn't get mainchain difficulty for height = %d: %s", block.Main.Coinbase.GenHeight, err)
		} else if isHigherMainChain {
			utils.Logf("SideChain", "add_external_block: block %s has enough PoW for Monero height %d, submitting it", templateId.String(), block.Main.Coinbase.GenHeight)
			c.server.SubmitBlock(&block.Main)
		}
		if isHigher, err := block.IsProofHigherThanDifficultyWithError(c.Consensus().GetHasher(), c.getSeedByHeightFunc()); err != nil {
			return nil, err, true
		} else if !isHigher {
			return nil, fmt.Errorf("not enough PoW for id %s, height = %d, mainchain height %d", templateId.String(), block.Side.Height, block.Main.Coinbase.GenHeight), true
		}
	}

	//TODO: block found section

	return missingBlocks, c.AddPoolBlock(block), true
}

func (c *SideChain) AddPoolBlock(block *PoolBlock) (err error) {

	c.sidechainLock.Lock()
	defer c.sidechainLock.Unlock()
	if c.blocksByTemplateId.Has(block.SideTemplateId(c.Consensus())) {
		//already inserted
		//TODO WARN
		return nil
	}

	if _, err := block.AppendBinaryFlags(c.preAllocatedBuffer, false, false); err != nil {
		return fmt.Errorf("encoding block error: %w", err)
	}

	c.blocksByTemplateId.Put(block.SideTemplateId(c.Consensus()), block)

	utils.Logf("SideChain", "add_block: height = %d, id = %s, mainchain height = %d, verified = %t, total = %d", block.Side.Height, block.SideTemplateId(c.Consensus()), block.Main.Coinbase.GenHeight, block.Verified.Load(), c.blocksByTemplateId.Count())

	if c.isWatched(block) {
		c.server.UpdateBlockFound(c.watchBlock, block)
		c.watchBlockPossibleId = types.ZeroHash
	}

	if l, ok := c.blocksByHeight.Get(block.Side.Height); ok {
		c.blocksByHeight.Put(block.Side.Height, append(l, block))
	} else {
		c.blocksByHeight.Put(block.Side.Height, []*PoolBlock{block})
		if !(c.blocksByHeightKeysSorted && len(c.blocksByHeightKeys) > 0 && c.blocksByHeightKeys[len(c.blocksByHeightKeys)-1]+1 == block.Side.Height) {
			c.blocksByHeightKeysSorted = false
		}
		c.blocksByHeightKeys = append(c.blocksByHeightKeys, block.Side.Height)
	}

	if block.ShareVersion() > ShareVersion_V2 {
		c.blocksByMerkleRoot.Put(block.MergeMiningTag().RootHash, block)
	}

	c.updateDepths(block)

	defer func() {
		if !block.Invalid.Load() && block.Depth.Load() == 0 {
			c.syncTip.Store(block)
		}
	}()

	if block.Verified.Load() {
		if !block.Invalid.Load() {
			c.updateChainTip(block)
		}

		return nil
	} else {
		return c.verifyLoop(block)
	}
}

func (c *SideChain) verifyLoop(blockToVerify *PoolBlock) (err error) {
	// PoW is already checked at this point

	blocksToVerify := make([]*PoolBlock, 1, 8)
	blocksToVerify[0] = blockToVerify
	var highestBlock *PoolBlock
	for len(blocksToVerify) != 0 {
		block := blocksToVerify[len(blocksToVerify)-1]
		blocksToVerify = blocksToVerify[:len(blocksToVerify)-1]

		if block.Verified.Load() {
			continue
		}

		if verification, invalid := c.verifyBlock(block); invalid != nil {
			utils.Logf("SideChain", "block at height = %d, id = %s, mainchain height = %d, mined by %s is invalid: %s", block.Side.Height, block.SideTemplateId(c.Consensus()), block.Main.Coinbase.GenHeight, block.GetAddress().ToBase58(c.Consensus().NetworkType.AddressNetwork()), invalid.Error())
			block.Invalid.Store(true)
			block.Verified.Store(verification == nil)
			if block == blockToVerify {
				//Save error for return
				err = invalid
			}
		} else if verification != nil {
			//utils.Logf("SideChain", "can't verify block at height = %d, id = %s, mainchain height = %d, mined by %s: %s", block.Side.Height, block.SideIdentifierHash(c.Consensus()), block.Main.Coinbase.GenHeight, block.GetAddress().ToBase58(), verification.Error())
			block.Verified.Store(false)
			block.Invalid.Store(false)
		} else {
			block.Verified.Store(true)
			block.Invalid.Store(false)

			if block.ShareVersion() > ShareVersion_V1 {
				utils.Logf("SideChain", "verified block at height = %d, depth = %d, id = %s, mainchain height = %d, mined by %s via %s %s", block.Side.Height, block.Depth.Load(), block.SideTemplateId(c.Consensus()), block.Main.Coinbase.GenHeight, block.GetAddress().ToBase58(c.Consensus().NetworkType.AddressNetwork()), block.Side.ExtraBuffer.SoftwareId, block.Side.ExtraBuffer.SoftwareVersion)
			} else {
				if signalingVersion := block.ShareVersionSignaling(); signalingVersion > ShareVersion_None {
					utils.Logf("SideChain", "verified block at height = %d, depth = %d, id = %s, mainchain height = %d, mined by %s, signaling v%d", block.Side.Height, block.Depth.Load(), block.SideTemplateId(c.Consensus()), block.Main.Coinbase.GenHeight, block.GetAddress().ToBase58(c.Consensus().NetworkType.AddressNetwork()), signalingVersion)
				} else {
					utils.Logf("SideChain", "verified block at height = %d, depth = %d, id = %s, mainchain height = %d, mined by %s", block.Side.Height, block.Depth.Load(), block.SideTemplateId(c.Consensus()), block.Main.Coinbase.GenHeight, block.GetAddress().ToBase58(c.Consensus().NetworkType.AddressNetwork()))
				}
			}

			// This block is now verified

			// Fill cache here

			if parent := c.getParent(block); parent != nil {
				block.iterationCache = &IterationCache{
					Parent: parent,
					Uncles: nil,
				}

				if len(block.Side.Uncles) > 0 {
					block.iterationCache.Uncles = make([]*PoolBlock, 0, len(block.Side.Uncles))
					for _, uncleId := range block.Side.Uncles {
						if uncle := c.getPoolBlockByTemplateId(uncleId); uncle == nil {
							block.iterationCache = nil
							break
						} else {
							block.iterationCache.Uncles = append(block.iterationCache.Uncles, uncle)
						}
					}
				}
			}

			c.fillPoolBlockTransactionParentIndices(block)

			if isLongerChain, _ := c.isLongerChain(highestBlock, block); isLongerChain {
				highestBlock = block
			} else if highestBlock != nil && highestBlock.Side.Height > block.Side.Height {
				utils.Logf("SideChain", "block at height = %d, id = %s, is not a longer chain than height = %d, id = %s", block.Side.Height, block.SideTemplateId(c.Consensus()), highestBlock.Side.Height, highestBlock.SideTemplateId(c.Consensus()))
			}

			if block.WantBroadcast.Load() && !block.Broadcasted.Swap(true) {
				if block.Depth.Load() < UncleBlockDepth {
					c.server.Broadcast(block)
				}
			}

			//store for faster startup
			go func() {
				c.server.Store(block)
				return
			}()

			// Try to verify blocks on top of this one
			for i := uint64(1); i <= UncleBlockDepth; i++ {
				blocksAtHeight, _ := c.blocksByHeight.Get(block.Side.Height + i)
				blocksToVerify = append(blocksToVerify, blocksAtHeight...)
			}
		}
	}

	if highestBlock != nil {
		c.updateChainTip(highestBlock)
	}

	return
}

func (c *SideChain) verifyBlock(block *PoolBlock) (verification error, invalid error) {
	// Genesis
	if block.Side.Height == 0 {
		if block.Side.Parent != types.ZeroHash ||
			len(block.Side.Uncles) != 0 ||
			block.Side.Difficulty.Cmp64(c.Consensus().MinimumDifficulty) != 0 ||
			block.Side.CumulativeDifficulty.Cmp64(c.Consensus().MinimumDifficulty) != 0 ||
			(block.ShareVersion() > ShareVersion_V1 && block.Side.CoinbasePrivateKeySeed != c.Consensus().Id) {
			return nil, errors.New("genesis block has invalid parameters")
		}
		//this does not verify coinbase outputs, but that's fine
		return nil, nil
	}

	// Deep block
	//
	// Blocks in PPLNS window (m_chainWindowSize) require up to m_chainWindowSize earlier blocks to verify
	// If a block is deeper than (m_chainWindowSize - 1) * 2 + UNCLE_BLOCK_DEPTH it can't influence blocks in PPLNS window
	// Also, having so many blocks on top of this one means it was verified by the network at some point
	// We skip checks in this case to make pruning possible
	if block.Depth.Load() > ((c.Consensus().ChainWindowSize-1)*2 + UncleBlockDepth) {
		utils.Logf("SideChain", "block at height = %d, id = %s skipped verification", block.Side.Height, block.SideTemplateId(c.Consensus()))
		return nil, nil
	}

	//Regular block
	//Must have parent
	if block.Side.Parent == types.ZeroHash {
		return nil, errors.New("block must have a parent")
	}

	if parent := c.getParent(block); parent != nil {
		// If it's invalid then this block is also invalid
		if !parent.Verified.Load() {
			return errors.New("parent is not verified"), nil
		}
		if parent.Invalid.Load() {
			return nil, errors.New("parent is invalid")
		}

		if block.ShareVersion() > ShareVersion_V1 {
			expectedSeed := parent.Side.CoinbasePrivateKeySeed
			if parent.Main.PreviousId != block.Main.PreviousId {
				expectedSeed = parent.CalculateTransactionPrivateKeySeed()
			}
			if block.Side.CoinbasePrivateKeySeed != expectedSeed {
				return nil, fmt.Errorf("invalid tx key seed: expected %s, got %s", expectedSeed.String(), block.Side.CoinbasePrivateKeySeed.String())
			}
		}

		expectedHeight := parent.Side.Height + 1
		if expectedHeight != block.Side.Height {
			return nil, fmt.Errorf("wrong height, expected %d", expectedHeight)
		}

		// Uncle hashes must be sorted in the ascending order to prevent cheating when the same hash is repeated multiple times
		for i, uncleId := range block.Side.Uncles {
			if i == 0 {
				continue
			}
			if block.Side.Uncles[i-1].Compare(uncleId) != -1 {
				return nil, errors.New("invalid uncle order")
			}
		}

		expectedCumulativeDifficulty := parent.Side.CumulativeDifficulty.Add(block.Side.Difficulty)

		//check uncles

		minedBlocks := c.preAllocatedMinedBlocks[:0]
		{
			tmp := parent
			n := min(UncleBlockDepth, block.Side.Height+1)
			for i := uint64(0); tmp != nil && i < n; i++ {
				minedBlocks = append(minedBlocks, tmp.SideTemplateId(c.Consensus()))
				for _, uncleId := range tmp.Side.Uncles {
					minedBlocks = append(minedBlocks, uncleId)
				}
				tmp = c.getParent(tmp)
			}
		}

		for _, uncleId := range block.Side.Uncles {
			// Empty hash is only used in the genesis block and only for its parent
			// Uncles can't be empty
			if uncleId == types.ZeroHash {
				return nil, errors.New("empty uncle hash")
			}

			// Can't mine the same uncle block twice
			if slices.Index(minedBlocks, uncleId) != -1 {
				return nil, fmt.Errorf("uncle %s has already been mined", uncleId.String())
			}

			if uncle := c.getPoolBlockByTemplateId(uncleId); uncle == nil {
				return errors.New("uncle does not exist"), nil
			} else if !uncle.Verified.Load() {
				// If it's invalid then this block is also invalid
				return errors.New("uncle is not verified"), nil
			} else if uncle.Invalid.Load() {
				// If it's invalid then this block is also invalid
				return nil, errors.New("uncle is invalid")
			} else if uncle.Side.Height >= block.Side.Height || (uncle.Side.Height+UncleBlockDepth < block.Side.Height) {
				return nil, fmt.Errorf("uncle at the wrong height (%d)", uncle.Side.Height)
			} else {
				// Check that uncle and parent have the same ancestor (they must be on the same chain)
				tmp := parent
				for tmp.Side.Height > uncle.Side.Height {
					tmp = c.getParent(tmp)
					if tmp == nil {
						return nil, errors.New("uncle from different chain (check 1)")
					}
				}

				if tmp.Side.Height < uncle.Side.Height {
					return nil, errors.New("uncle from different chain (check 2)")
				}

				if sameChain := func() bool {
					tmp2 := uncle
					for j := uint64(0); j < UncleBlockDepth && tmp != nil && tmp2 != nil && (tmp.Side.Height+UncleBlockDepth >= block.Side.Height); j++ {
						if tmp.Side.Parent == tmp2.Side.Parent {
							return true
						}
						tmp = c.getParent(tmp)
						tmp2 = c.getParent(tmp2)
					}
					return false
				}(); !sameChain {
					return nil, errors.New("uncle from different chain (check 3)")
				}

				expectedCumulativeDifficulty = expectedCumulativeDifficulty.Add(uncle.Side.Difficulty)

			}

		}

		// We can verify this block now (all previous blocks in the window are verified and valid)
		// It can still turn out to be invalid

		if !block.Side.CumulativeDifficulty.Equals(expectedCumulativeDifficulty) {
			return nil, fmt.Errorf("wrong cumulative difficulty, got %s, expected %s", block.Side.CumulativeDifficulty.StringNumeric(), expectedCumulativeDifficulty.StringNumeric())
		}

		// Verify difficulty and miner rewards only for blocks in PPLNS window
		if block.Depth.Load() >= c.Consensus().ChainWindowSize {
			utils.Logf("SideChain", "block at height = %d, id = %s skipped diff/reward verification", block.Side.Height, block.SideTemplateId(c.Consensus()))
			return
		}

		var diff types.Difficulty

		if parent == c.GetChainTip() {
			// built on top of the current chain tip, using current difficulty for verification
			diff = c.Difficulty()
		} else if diff, verification, invalid = c.getDifficulty(parent); verification != nil || invalid != nil {
			return verification, invalid
		} else if diff == types.ZeroDifficulty {
			return nil, errors.New("could not get difficulty")
		}
		if diff != block.Side.Difficulty {
			return nil, fmt.Errorf("wrong difficulty, got %s, expected %s", block.Side.Difficulty.StringNumeric(), diff.StringNumeric())
		}

		if shares, _ := c.getShares(block, c.preAllocatedShares); len(shares) == 0 {
			return nil, errors.New("could not get outputs")
		} else if len(shares) != len(block.Main.Coinbase.Outputs) {
			return nil, fmt.Errorf("invalid number of outputs, got %d, expected %d", len(block.Main.Coinbase.Outputs), len(shares))
		} else if totalReward := func() (result uint64) {
			for _, o := range block.Main.Coinbase.Outputs {
				result += o.Reward
			}
			return
		}(); totalReward != block.Main.Coinbase.AuxiliaryData.TotalReward {
			return nil, fmt.Errorf("invalid total reward, got %d, expected %d", block.Main.Coinbase.AuxiliaryData.TotalReward, totalReward)
		} else if rewards := SplitReward(c.preAllocatedRewards, totalReward, shares); len(rewards) != len(block.Main.Coinbase.Outputs) {
			return nil, fmt.Errorf("invalid number of outputs, got %d, expected %d", len(block.Main.Coinbase.Outputs), len(rewards))
		} else {

			//prevent multiple allocations
			txPrivateKeySlice := block.Side.CoinbasePrivateKey.AsSlice()
			txPrivateKeyScalar := block.Side.CoinbasePrivateKey.AsScalar()

			var hashers []*sha3.HasherState

			defer func() {
				for _, h := range hashers {
					crypto.PutKeccak256Hasher(h)
				}
			}()

			if err := utils.SplitWork(-2, uint64(len(rewards)), func(workIndex uint64, workerIndex int) error {
				out := block.Main.Coinbase.Outputs[workIndex]
				if rewards[workIndex] != out.Reward {
					return fmt.Errorf("has invalid reward at index %d, got %d, expected %d", workIndex, out.Reward, rewards[workIndex])
				}

				if ephPublicKey, viewTag := c.derivationCache.GetEphemeralPublicKey(&shares[workIndex].Address, txPrivateKeySlice, txPrivateKeyScalar, workIndex, hashers[workerIndex]); ephPublicKey != out.EphemeralPublicKey {
					return fmt.Errorf("has incorrect eph_public_key at index %d, got %s, expected %s", workIndex, out.EphemeralPublicKey.String(), ephPublicKey.String())
				} else if out.Type == transaction.TxOutToTaggedKey && viewTag != out.ViewTag {
					return fmt.Errorf("has incorrect view tag at index %d, got %d, expected %d", workIndex, out.ViewTag, viewTag)
				}
				return nil
			}, func(routines, routineIndex int) error {
				hashers = append(hashers, crypto.GetKeccak256Hasher())
				return nil
			}); err != nil {
				return nil, err
			}
		}

		// All checks passed
		return nil, nil
	} else {
		return errors.New("parent does not exist"), nil
	}
}

func (c *SideChain) updateDepths(block *PoolBlock) {
	preCalcDepth := c.Consensus().ChainWindowSize + UncleBlockDepth - 1

	updateDepth := func(b *PoolBlock, newDepth uint64) {
		oldDepth := b.Depth.Load()
		if oldDepth < newDepth {
			b.Depth.Store(newDepth)
			if oldDepth < preCalcDepth && newDepth >= preCalcDepth {
				//TODO launchPrecalc
			}
		}
	}

	for i := uint64(1); i <= UncleBlockDepth; i++ {
		blocksAtHeight, _ := c.blocksByHeight.Get(block.Side.Height + i)
		for _, child := range blocksAtHeight {
			if child.Side.Parent == block.SideTemplateId(c.Consensus()) {
				if i != 1 {
					utils.Logf("SideChain", "Block %s side height %d is inconsistent with child's side_height %d", block.SideTemplateId(c.Consensus()), block.Side.Height, child.Side.Height)
					return
				} else {
					updateDepth(block, child.Depth.Load()+1)
				}
			}

			if ix := slices.Index(child.Side.Uncles, block.SideTemplateId(c.Consensus())); ix != 1 {
				updateDepth(block, child.Depth.Load()+1)
			}
		}
	}

	blocksToUpdate := make([]*PoolBlock, 1, 8)
	blocksToUpdate[0] = block

	for len(blocksToUpdate) != 0 {
		block = blocksToUpdate[len(blocksToUpdate)-1]
		blocksToUpdate = blocksToUpdate[:len(blocksToUpdate)-1]

		blockDepth := block.Depth.Load()

		// Verify this block and possibly other blocks on top of it when we're sure it will get verified
		if !block.Verified.Load() && (blockDepth > ((c.Consensus().ChainWindowSize-1)*2+UncleBlockDepth) || block.Side.Height == 0) {
			_ = c.verifyLoop(block)
		}

		for i := uint64(1); i <= UncleBlockDepth; i++ {
			for _, child := range c.getPoolBlocksByHeight(block.Side.Height + i) {
				oldDepth := child.Depth.Load()

				if child.Side.Parent == block.SideTemplateId(c.Consensus()) {
					if i != 1 {
						utils.Logf("SideChain", "Block %s side height %d is inconsistent with child's side_height %d", block.SideTemplateId(c.Consensus()), block.Side.Height, child.Side.Height)
						return
					} else if blockDepth > 0 {
						updateDepth(child, blockDepth-1)
					}
				}

				if slices.Contains(child.Side.Uncles, block.SideTemplateId(c.Consensus())) {
					if blockDepth > i {
						updateDepth(child, blockDepth-i)
					}
				}

				if child.Depth.Load() > oldDepth {
					blocksToUpdate = append(blocksToUpdate, child)
				}
			}
		}

		if parent := block.iteratorGetParent(c.getPoolBlockByTemplateId); parent != nil {
			if parent.Side.Height+1 != block.Side.Height {
				utils.Logf("SideChain", "Block %s side height %d is inconsistent with parent's side_height %d", block.SideTemplateId(c.Consensus()), block.Side.Height, parent.Side.Height)
				return
			}

			if parent.Depth.Load() < blockDepth+1 {
				updateDepth(parent, blockDepth+1)
				blocksToUpdate = append(blocksToUpdate, parent)
			}
		}

		var returnFromUncles bool

		_ = block.iteratorUncles(c.getPoolBlockByTemplateId, func(uncle *PoolBlock) {
			if uncle.Side.Height >= block.Side.Height || (uncle.Side.Height+UncleBlockDepth < block.Side.Height) {
				utils.Logf("SideChain", "Block %s side height %d is inconsistent with uncle's side_height %d", block.SideTemplateId(c.Consensus()), block.Side.Height, uncle.Side.Height)
				returnFromUncles = true
				return
			}

			d := block.Side.Height - uncle.Side.Height
			if uncle.Depth.Load() < blockDepth+d {
				updateDepth(uncle, blockDepth+d)
				blocksToUpdate = append(blocksToUpdate, uncle)
			}
		})
		if returnFromUncles {
			return
		}
	}
}

func (c *SideChain) updateChainTip(block *PoolBlock) {
	if !block.Verified.Load() || block.Invalid.Load() {
		//todo err
		return
	}

	if block.Depth.Load() >= c.Consensus().ChainWindowSize {
		//TODO err
		return
	}

	tip := c.GetChainTip()

	if block == tip {
		utils.Logf("SideChain", "Trying to update chain tip to the same block again. Ignoring it.")
		return
	}

	if isLongerChain, isAlternative := c.isLongerChain(tip, block); isLongerChain {
		if diff, _, _ := c.getDifficulty(block); diff != types.ZeroDifficulty {
			c.chainTip.Store(block)
			c.syncTip.Store(block)
			c.currentDifficulty.Store(&diff)
			//TODO log

			block.WantBroadcast.Store(true)
			c.server.UpdateTip(block)

			if isAlternative {
				c.precalcFinished.Store(true)
				c.derivationCache.Clear()

				utils.Logf("SideChain", "SYNCHRONIZED to tip %s", block.SideTemplateId(c.Consensus()))
			}

			c.pruneOldBlocks()
		}
	} else if block.Side.Height > tip.Side.Height {
		utils.Logf("SideChain", "block %s, height = %d, is not a longer chain than %s, height = %d", block.SideTemplateId(c.Consensus()), block.Side.Height, tip.SideTemplateId(c.Consensus()), tip.Side.Height)
	} else if block.Side.Height+UncleBlockDepth > tip.Side.Height {
		utils.Logf("SideChain", "possible uncle block: id = %s, height = %d", block.SideTemplateId(c.Consensus()), block.Side.Height)
	}

	if block.WantBroadcast.Load() && !block.Broadcasted.Swap(true) {
		c.server.Broadcast(block)
	}

}

func (c *SideChain) pruneOldBlocks() {

	// Leave 2 minutes worth of spare blocks in addition to 2xPPLNS window for lagging nodes which need to sync
	pruneDistance := c.Consensus().ChainWindowSize*2 + monero.BlockTime/c.Consensus().TargetBlockTime

	curTime := uint64(time.Now().Unix())

	// Remove old blocks from alternative unconnected chains after long enough time
	pruneDelay := c.Consensus().ChainWindowSize * 4 * c.Consensus().TargetBlockTime

	tip := c.GetChainTip()
	if tip == nil || tip.Side.Height < pruneDistance {
		return
	}

	h := tip.Side.Height - pruneDistance

	if !c.blocksByHeightKeysSorted {
		slices.Sort(c.blocksByHeightKeys)
		c.blocksByHeightKeysSorted = true
	}

	numBlocksPruned := 0

	for keyIndex, height := range c.blocksByHeightKeys {
		// Early exit
		if height > h {
			break
		}

		v, _ := c.blocksByHeight.Get(height)

		// loop backwards for proper deletions
		for i := len(v) - 1; i >= 0; i-- {
			block := v[i]
			if block.Depth.Load() >= pruneDistance || (curTime >= (block.LocalTimestamp + pruneDelay)) {
				templateId := block.SideTemplateId(c.Consensus())
				if c.blocksByTemplateId.Has(templateId) {
					c.blocksByTemplateId.Delete(templateId)
					numBlocksPruned++
				} else {
					utils.Logf("SideChain", "blocksByHeight and blocksByTemplateId are inconsistent at height = %d, id = %s", height, templateId)
				}

				if block.ShareVersion() > ShareVersion_V2 {
					rootHash := block.MergeMiningTag().RootHash
					if c.blocksByMerkleRoot.Has(rootHash) {
						c.blocksByMerkleRoot.Delete(rootHash)
					} else {
						utils.Logf("SideChain", "blocksByHeight and m_blocksByMerkleRoot are inconsistent at height = %d, id = %s", height, rootHash)
					}
				}

				v = slices.Delete(v, i, i+1)

				// Empty cache here
				block.iterationCache = nil
			}
		}

		if len(v) == 0 {
			c.blocksByHeight.Delete(height)
			c.blocksByHeightKeys = slices.Delete(c.blocksByHeightKeys, keyIndex, keyIndex+1)
		} else {
			c.blocksByHeight.Put(height, v)
		}
	}

	if numBlocksPruned > 0 {
		utils.Logf("SideChain", "pruned %d old blocks at heights <= %d", numBlocksPruned, h)
		if !c.precalcFinished.Swap(true) {
			c.derivationCache.Clear()
		}

		numSeenBlocksPruned := c.cleanupSeenBlocks()
		if numSeenBlocksPruned > 0 {
			//utils.Logf("SideChain", "pruned %d seen blocks", numBlocksPruned)
		}
	}
}

func (c *SideChain) cleanupSeenBlocks() (cleaned int) {
	c.seenBlocksLock.Lock()
	defer c.seenBlocksLock.Unlock()

	c.seenBlocks.Iter(func(k FullId, _ struct{}) (stop bool) {
		if c.getPoolBlockByTemplateId(k.TemplateId()) == nil {
			c.seenBlocks.Delete(k)
			cleaned++
		}
		return false
	})
	return cleaned
}

func (c *SideChain) GetMissingBlocks() []types.Hash {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()

	missingBlocks := make([]types.Hash, 0)

	c.blocksByTemplateId.Iter(func(_ types.Hash, b *PoolBlock) (stop bool) {
		if b.Verified.Load() {
			return false
		}

		if b.Side.Parent != types.ZeroHash && c.getPoolBlockByTemplateId(b.Side.Parent) == nil {
			missingBlocks = append(missingBlocks, b.Side.Parent)
		}

		missingUncles := 0

		for _, uncleId := range b.Side.Uncles {
			if uncleId != types.ZeroHash && c.getPoolBlockByTemplateId(uncleId) == nil {
				missingBlocks = append(missingBlocks, uncleId)
				missingUncles++

				// Get no more than 2 first missing uncles at a time from each block
				// Blocks with more than 2 uncles are very rare and they will be processed in several steps
				if missingUncles >= 2 {
					return true
				}
			}
		}
		return false
	})

	return missingBlocks
}

// calculateOutputs
// Deprecated
func (c *SideChain) calculateOutputs(block *PoolBlock) (outputs transaction.Outputs, bottomHeight uint64) {
	preAllocatedShares := c.preAllocatedSharesPool.Get()
	defer c.preAllocatedSharesPool.Put(preAllocatedShares)
	return CalculateOutputs(block, c.Consensus(), c.server.GetDifficultyByHeight, c.getPoolBlockByTemplateId, c.derivationCache, preAllocatedShares, c.preAllocatedRewards)
}

func (c *SideChain) Server() P2PoolInterface {
	return c.server
}

func (c *SideChain) getShares(tip *PoolBlock, preAllocatedShares Shares) (shares Shares, bottomHeight uint64) {
	return GetShares(tip, c.Consensus(), c.server.GetDifficultyByHeight, c.getPoolBlockByTemplateId, preAllocatedShares)
}

func (c *SideChain) GetDifficulty(tip *PoolBlock) (difficulty types.Difficulty, verifyError, invalidError error) {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	return c.getDifficulty(tip)
}

func (c *SideChain) getDifficulty(tip *PoolBlock) (difficulty types.Difficulty, verifyError, invalidError error) {
	return GetDifficultyForNextBlock(tip, c.Consensus(), c.getPoolBlockByTemplateId, c.preAllocatedDifficultyData, c.preAllocatedTimestampData)
}

func (c *SideChain) GetParent(block *PoolBlock) *PoolBlock {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	return c.getParent(block)
}

func (c *SideChain) getParent(block *PoolBlock) *PoolBlock {
	return block.iteratorGetParent(c.getPoolBlockByTemplateId)
}

func (c *SideChain) GetPoolBlockByTemplateId(id types.Hash) *PoolBlock {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	return c.getPoolBlockByTemplateId(id)
}

func (c *SideChain) getPoolBlockByTemplateId(id types.Hash) *PoolBlock {
	b, _ := c.blocksByTemplateId.Get(id)
	return b
}

func (c *SideChain) GetPoolBlockByMerkleRoot(id types.Hash) *PoolBlock {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	return c.getPoolBlockByMerkleRoot(id)
}

func (c *SideChain) getPoolBlockByMerkleRoot(id types.Hash) *PoolBlock {
	b, _ := c.blocksByMerkleRoot.Get(id)
	return b
}

func (c *SideChain) GetPoolBlocksByHeight(height uint64) []*PoolBlock {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	return slices.Clone(c.getPoolBlocksByHeight(height))
}

func (c *SideChain) getPoolBlocksByHeight(height uint64) []*PoolBlock {
	b, _ := c.blocksByHeight.Get(height)
	return b
}

func (c *SideChain) GetPoolBlocksFromTip(id types.Hash) (chain, uncles UniquePoolBlockSlice) {
	chain = make([]*PoolBlock, 0, c.Consensus().ChainWindowSize*2+monero.BlockTime/c.Consensus().TargetBlockTime)
	uncles = make([]*PoolBlock, 0, len(chain)/20)

	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	for cur := c.getPoolBlockByTemplateId(id); cur != nil; cur = c.getPoolBlockByTemplateId(cur.Side.Parent) {
		for i, uncleId := range cur.Side.Uncles {
			if u := c.getPoolBlockByTemplateId(uncleId); u == nil {
				//return few uncles than necessary
				return chain, uncles[:len(uncles)-i]
			} else {
				uncles = append(uncles, u)
			}
		}
		chain = append(chain, cur)
	}

	return chain, uncles
}

func (c *SideChain) GetPoolBlocksFromTipWithDepth(id types.Hash, depth uint64) (chain, uncles UniquePoolBlockSlice) {
	chain = make([]*PoolBlock, 0, min(depth, c.Consensus().ChainWindowSize*2+monero.BlockTime/c.Consensus().TargetBlockTime))
	uncles = make([]*PoolBlock, 0, len(chain)/20)

	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	for cur := c.getPoolBlockByTemplateId(id); cur != nil && len(chain) < int(depth); cur = c.getPoolBlockByTemplateId(cur.Side.Parent) {
		for i, uncleId := range cur.Side.Uncles {
			if u := c.getPoolBlockByTemplateId(uncleId); u == nil {
				//return few uncles than necessary
				return chain, uncles[:len(uncles)-i]
			} else {
				uncles = append(uncles, u)
			}
		}
		chain = append(chain, cur)
	}

	return chain, uncles
}

func (c *SideChain) GetPoolBlockCount() int {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	return c.blocksByTemplateId.Count()
}

func (c *SideChain) WatchMainChainBlock(mainData *ChainMain, possibleId types.Hash) {
	c.sidechainLock.Lock()
	defer c.sidechainLock.Unlock()

	c.watchBlock = mainData
	c.watchBlockPossibleId = possibleId
}

func (c *SideChain) GetHighestKnownTip() *PoolBlock {
	if t := c.chainTip.Load(); t != nil {
		return t
	}
	return c.syncTip.Load()
}

func (c *SideChain) GetChainTip() *PoolBlock {
	return c.chainTip.Load()
}

func (c *SideChain) LastUpdated() uint64 {
	if tip := c.chainTip.Load(); tip != nil {
		return tip.LocalTimestamp
	}
	return 0
}

func (c *SideChain) IsLongerChain(block, candidate *PoolBlock) (isLonger, isAlternative bool) {
	c.sidechainLock.RLock()
	defer c.sidechainLock.RUnlock()
	return c.isLongerChain(block, candidate)
}

func (c *SideChain) isLongerChain(block, candidate *PoolBlock) (isLonger, isAlternative bool) {
	return IsLongerChain(block, candidate, c.Consensus(), c.getPoolBlockByTemplateId, func(h types.Hash) *ChainMain {
		if h == types.ZeroHash {
			return c.server.GetChainMainTip()
		}
		return c.server.GetChainMainByHash(h)
	})
}

func LoadSideChainTestData(c *SideChain, reader io.Reader, patchedBlocks ...[]byte) error {
	var err error
	buf := make([]byte, PoolBlockMaxTemplateSize)

	blocks := make([]*PoolBlock, 0, c.Consensus().ChainWindowSize*3)

	for {
		buf = buf[:0]
		var blockLen uint32
		if err = binary.Read(reader, binary.LittleEndian, &blockLen); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if _, err = io.ReadFull(reader, buf[:blockLen]); err != nil {
			return err
		}
		b := &PoolBlock{}
		if err = b.UnmarshalBinary(c.Consensus(), c.DerivationCache(), buf[:blockLen]); err != nil {
			return err
		}
		blocks = append(blocks, b)
	}

	for _, buf := range patchedBlocks {
		b := &PoolBlock{}
		if err = b.UnmarshalBinary(c.Consensus(), c.DerivationCache(), buf); err != nil {
			return err
		}
		blocks = append(blocks, b)
	}

	// Shuffle blocks. This allows testing proper reorg
	unsafeRandom.Shuffle(len(blocks), func(i, j int) {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	})

	for _, b := range blocks {
		// verify externally first without PoW, then add directly
		if _, err, _ = c.PoolBlockExternalVerify(b); err != nil {
			return err
		}
		if err = c.AddPoolBlock(b); err != nil {
			return err
		}
	}

	return nil
}
