package mainchain

import (
	"bytes"
	"context"
	"fmt"
	"git.gammaspectra.live/P2Pool/consensus/v3/merge_mining"
	mainblock "git.gammaspectra.live/P2Pool/consensus/v3/monero/block"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/client/zmq"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v3/p2pool/mempool"
	"git.gammaspectra.live/P2Pool/consensus/v3/p2pool/sidechain"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v3/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/utils"
	"github.com/dolthub/swiss"
	fasthex "github.com/tmthrgd/go-hex"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const TimestampWindow = 60
const BlockHeadersRequired = 720

type MainChain struct {
	p2pool    P2PoolInterface
	lock      sync.RWMutex
	sidechain *sidechain.SideChain

	highest           uint64
	mainchainByHeight *swiss.Map[uint64, *sidechain.ChainMain]
	mainchainByHash   *swiss.Map[types.Hash, *sidechain.ChainMain]

	tip          atomic.Pointer[sidechain.ChainMain]
	tipMinerData atomic.Pointer[p2pooltypes.MinerData]

	medianTimestamp atomic.Uint64
}

type P2PoolInterface interface {
	ClientRPC() *client.Client
	ClientZMQ() *zmq.Client
	Context() context.Context
	Started() bool
	UpdateMainData(data *sidechain.ChainMain)
	UpdateMinerData(data *p2pooltypes.MinerData)
	UpdateMempoolData(data mempool.Mempool)
	UpdateBlockFound(data *sidechain.ChainMain, block *sidechain.PoolBlock)
}

func NewMainChain(s *sidechain.SideChain, p2pool P2PoolInterface) *MainChain {
	m := &MainChain{
		sidechain:         s,
		p2pool:            p2pool,
		mainchainByHeight: swiss.NewMap[uint64, *sidechain.ChainMain](BlockHeadersRequired + 3),
		mainchainByHash:   swiss.NewMap[types.Hash, *sidechain.ChainMain](BlockHeadersRequired + 3),
	}

	return m
}

func (c *MainChain) Listen() error {
	ctx := c.p2pool.Context()
	err := c.p2pool.ClientZMQ().Listen(ctx,
		func(fullChainMain *zmq.FullChainMain) {
			if len(fullChainMain.MinerTx.Inputs) < 1 {
				return
			}
			d := &sidechain.ChainMain{
				Difficulty: types.ZeroDifficulty,
				Height:     fullChainMain.MinerTx.Inputs[0].Gen.Height,
				Timestamp:  uint64(fullChainMain.Timestamp),
				Reward:     0,
				Id:         types.ZeroHash,
			}
			for _, o := range fullChainMain.MinerTx.Outputs {
				d.Reward += o.Amount
			}

			outputs := make(transaction.Outputs, 0, len(fullChainMain.MinerTx.Outputs))
			var totalReward uint64
			for i, o := range fullChainMain.MinerTx.Outputs {
				if o.ToKey != nil {
					outputs = append(outputs, transaction.Output{
						Index:              uint64(i),
						Reward:             o.Amount,
						Type:               transaction.TxOutToKey,
						EphemeralPublicKey: o.ToKey.Key,
						ViewTag:            0,
					})
				} else if o.ToTaggedKey != nil {
					tk, _ := fasthex.DecodeString(o.ToTaggedKey.ViewTag)
					outputs = append(outputs, transaction.Output{
						Index:              uint64(i),
						Reward:             o.Amount,
						Type:               transaction.TxOutToTaggedKey,
						EphemeralPublicKey: o.ToTaggedKey.Key,
						ViewTag:            tk[0],
					})
				} else {
					//error
					break
				}
				totalReward += o.Amount
			}

			if len(outputs) != len(fullChainMain.MinerTx.Outputs) {
				return
			}

			extraDataRaw, _ := fasthex.DecodeString(fullChainMain.MinerTx.Extra)
			extraTags := transaction.ExtraTags{}
			if err := extraTags.UnmarshalBinary(extraDataRaw); err != nil {
				//TODO: err
				extraTags = nil
			}

			blockData := &mainblock.Block{
				MajorVersion: uint8(fullChainMain.MajorVersion),
				MinorVersion: uint8(fullChainMain.MinorVersion),
				Timestamp:    uint64(fullChainMain.Timestamp),
				PreviousId:   fullChainMain.PrevID,
				Nonce:        uint32(fullChainMain.Nonce),
				Coinbase: transaction.CoinbaseTransaction{
					Version:      uint8(fullChainMain.MinerTx.Version),
					UnlockTime:   uint64(fullChainMain.MinerTx.UnlockTime),
					InputCount:   uint8(len(fullChainMain.MinerTx.Inputs)),
					InputType:    transaction.TxInGen,
					GenHeight:    fullChainMain.MinerTx.Inputs[0].Gen.Height,
					Outputs:      outputs,
					Extra:        extraTags,
					ExtraBaseRCT: 0,
					AuxiliaryData: transaction.CoinbaseTransactionAuxiliaryData{
						OutputsBlobSize: 0,
						TotalReward:     totalReward,
					},
				},
				Transactions:             fullChainMain.TxHashes,
				TransactionParentIndices: nil,
			}
			c.HandleMainBlock(blockData)
		},
		func(txs []zmq.FullTxPoolAdd) {},
		func(fullMinerData *zmq.FullMinerData) {
			c.HandleMinerData(&p2pooltypes.MinerData{
				MajorVersion:          fullMinerData.MajorVersion,
				Height:                fullMinerData.Height,
				PrevId:                fullMinerData.PrevId,
				SeedHash:              fullMinerData.SeedHash,
				Difficulty:            fullMinerData.Difficulty,
				MedianWeight:          fullMinerData.MedianWeight,
				AlreadyGeneratedCoins: fullMinerData.AlreadyGeneratedCoins,
				MedianTimestamp:       fullMinerData.MedianTimestamp,
				TxBacklog:             fullMinerData.TxBacklog,
				TimeReceived:          time.Now(),
			})
		},
		func(chainMain *zmq.MinimalChainMain) {},
		c.p2pool.UpdateMempoolData,
	)
	if err != nil {
		return err
	}
	return nil
}

func (c *MainChain) getTimestamps(timestamps []uint64) bool {
	_ = timestamps[TimestampWindow-1]
	if c.mainchainByHeight.Count() <= TimestampWindow {
		return false
	}

	for i := 0; i < TimestampWindow; i++ {
		h, ok := c.mainchainByHeight.Get(c.highest - uint64(i))
		if !ok {
			break
		}
		timestamps[i] = h.Timestamp
	}
	return true
}

func (c *MainChain) updateMedianTimestamp() {
	var timestamps [TimestampWindow]uint64
	if !c.getTimestamps(timestamps[:]) {
		c.medianTimestamp.Store(0)
		return
	}

	slices.Sort(timestamps[:])

	// Shift it +1 block compared to Monero's code because we don't have the latest block yet when we receive new miner data
	ts := (timestamps[TimestampWindow/2] + timestamps[TimestampWindow/2+1]) / 2
	utils.Logf("MainChain", "Median timestamp updated to %d", ts)
	c.medianTimestamp.Store(ts)
}

func (c *MainChain) HandleMainHeader(mainHeader *mainblock.Header) {
	c.lock.Lock()
	defer c.lock.Unlock()

	mainData := &sidechain.ChainMain{
		Difficulty: mainHeader.Difficulty,
		Height:     mainHeader.Height,
		Timestamp:  mainHeader.Timestamp,
		Reward:     mainHeader.Reward,
		Id:         mainHeader.Id,
	}
	c.mainchainByHeight.Put(mainHeader.Height, mainData)
	c.mainchainByHash.Put(mainHeader.Id, mainData)

	if mainData.Height > c.highest {
		c.highest = mainData.Height
	}

	utils.Logf("MainChain", "new main chain block: height = %d, id = %s, timestamp = %d, reward = %s", mainData.Height, mainData.Id.String(), mainData.Timestamp, utils.XMRUnits(mainData.Reward))

	c.updateMedianTimestamp()
}

func (c *MainChain) HandleMainBlock(b *mainblock.Block) {
	mainData := &sidechain.ChainMain{
		Difficulty: types.ZeroDifficulty,
		Height:     b.Coinbase.GenHeight,
		Timestamp:  b.Timestamp,
		Reward:     b.Coinbase.AuxiliaryData.TotalReward,
		Id:         b.Id(),
	}

	func() {
		c.lock.Lock()
		defer c.lock.Unlock()

		if h, ok := c.mainchainByHeight.Get(mainData.Height); ok {
			mainData.Difficulty = h.Difficulty
		} else {
			return
		}
		c.mainchainByHash.Put(mainData.Id, mainData)
		c.mainchainByHeight.Put(mainData.Height, mainData)

		if mainData.Height > c.highest {
			c.highest = mainData.Height
		}

		utils.Logf("MainChain", "new main chain block: height = %d, id = %s, timestamp = %d, reward = %s", mainData.Height, mainData.Id.String(), mainData.Timestamp, utils.XMRUnits(mainData.Reward))

		c.updateMedianTimestamp()
	}()

	defer c.updateTip()

	mergeMineTag := b.Coinbase.Extra.GetTag(transaction.TxExtraTagMergeMining)
	if mergeMineTag == nil {
		return
	}

	shareVersion := sidechain.P2PoolShareVersion(c.sidechain.Consensus(), mainData.Timestamp)

	if shareVersion <= sidechain.ShareVersion_V2 {
		//TODO: this is to comply with non-standard p2pool serialization, see https://github.com/SChernykh/p2pool/issues/249
		if mergeMineTag.VarInt != types.HashSize {
			return
		}

		if len(mergeMineTag.Data) != types.HashSize {
			return
		}

		sidechainId := types.HashFromBytes(mergeMineTag.Data)

		if block := c.sidechain.GetPoolBlockByTemplateId(sidechainId); block != nil {
			c.p2pool.UpdateBlockFound(mainData, block)
		} else {
			c.sidechain.WatchMainChainBlock(mainData, sidechainId)
		}
	} else {
		//properly decode merge mining tag
		mergeMineReader := bytes.NewReader(mergeMineTag.Data)
		var mergeMiningTag merge_mining.Tag
		if err := mergeMiningTag.FromReader(mergeMineReader); err != nil {
			return
		}
		if mergeMineReader.Len() != 0 {
			return
		}

		if block := c.sidechain.GetPoolBlockByTemplateId(mergeMiningTag.RootHash); block != nil {
			c.p2pool.UpdateBlockFound(mainData, block)
		} else {
			c.sidechain.WatchMainChainBlock(mainData, mergeMiningTag.RootHash)
		}
	}
}

func (c *MainChain) GetChainMainByHeight(height uint64) *sidechain.ChainMain {
	c.lock.RLock()
	defer c.lock.RUnlock()
	m, _ := c.mainchainByHeight.Get(height)
	return m
}

func (c *MainChain) GetChainMainByHash(hash types.Hash) *sidechain.ChainMain {
	c.lock.RLock()
	defer c.lock.RUnlock()
	b, _ := c.mainchainByHash.Get(hash)
	return b
}

func (c *MainChain) GetChainMainTip() *sidechain.ChainMain {
	return c.tip.Load()
}

func (c *MainChain) GetMinerDataTip() *p2pooltypes.MinerData {
	return c.tipMinerData.Load()
}

func (c *MainChain) updateTip() {
	if minerData := c.tipMinerData.Load(); minerData != nil {
		if d := c.GetChainMainByHash(minerData.PrevId); d != nil {
			c.tip.Store(d)
		}
	}
}

func (c *MainChain) Cleanup() {
	if tip := c.GetChainMainTip(); tip != nil {
		c.lock.Lock()
		defer c.lock.Unlock()
		c.cleanup(tip.Height)
	}
}

func (c *MainChain) cleanup(height uint64) {
	// Expects m_mainchainLock to be already locked here
	// Deletes everything older than 720 blocks, except for the 3 latest RandomX seed heights

	const PruneDistance = BlockHeadersRequired

	seedHeight := randomx.SeedHeight(height)

	seedHeights := []uint64{seedHeight, seedHeight - randomx.SeedHashEpochBlocks, seedHeight - randomx.SeedHashEpochBlocks*2}

	c.mainchainByHeight.Iter(func(h uint64, m *sidechain.ChainMain) (stop bool) {
		if (h + PruneDistance) >= height {
			return false
		}

		if !slices.Contains(seedHeights, h) {
			c.mainchainByHash.Delete(m.Id)
			c.mainchainByHeight.Delete(h)
		}
		return false
	})

}

func (c *MainChain) DownloadBlockHeaders(currentHeight uint64) error {
	seedHeight := randomx.SeedHeight(currentHeight)

	var prevSeedHeight uint64

	if seedHeight > randomx.SeedHashEpochBlocks {
		prevSeedHeight = seedHeight - randomx.SeedHashEpochBlocks
	}

	// First download 2 RandomX seeds

	for _, h := range []uint64{prevSeedHeight, seedHeight} {
		if err := c.getBlockHeader(h); err != nil {
			return err
		}
	}

	var startHeight uint64
	if currentHeight > BlockHeadersRequired {
		startHeight = currentHeight - BlockHeadersRequired
	}

	if rangeResult, err := c.p2pool.ClientRPC().GetBlockHeadersRangeResult(startHeight, currentHeight-1, c.p2pool.Context()); err != nil {
		return fmt.Errorf("couldn't download block headers range for height %d to %d: %s", startHeight, currentHeight-1, err)
	} else {
		for _, header := range rangeResult.Headers {
			c.HandleMainHeader(&mainblock.Header{
				MajorVersion: uint8(header.MajorVersion),
				MinorVersion: uint8(header.MinorVersion),
				Timestamp:    uint64(header.Timestamp),
				PreviousId:   header.PrevHash,
				Height:       header.Height,
				Nonce:        uint32(header.Nonce),
				Reward:       header.Reward,
				Id:           header.Hash,
				Difficulty:   types.NewDifficulty(header.Difficulty, header.DifficultyTop64),
			})
		}
		utils.Logf("MainChain", "Downloaded headers for range %d to %d", startHeight, currentHeight-1)
	}

	c.updateMedianTimestamp()

	return nil
}

func (c *MainChain) HandleMinerData(minerData *p2pooltypes.MinerData) {
	var missingHeights []uint64
	func() {
		c.lock.Lock()
		defer c.lock.Unlock()

		mainData := &sidechain.ChainMain{
			Difficulty: minerData.Difficulty,
			Height:     minerData.Height,
		}

		if existingMainData, ok := c.mainchainByHeight.Get(mainData.Height); !ok {
			c.mainchainByHeight.Put(mainData.Height, mainData)
		} else {
			existingMainData.Difficulty = mainData.Difficulty
			mainData = existingMainData
		}

		prevMainData := &sidechain.ChainMain{
			Height: minerData.Height - 1,
			Id:     minerData.PrevId,
		}

		if existingPrevMainData, ok := c.mainchainByHeight.Get(prevMainData.Height); !ok {
			c.mainchainByHeight.Put(prevMainData.Height, prevMainData)
		} else {
			existingPrevMainData.Id = prevMainData.Id

			prevMainData = existingPrevMainData
		}

		c.mainchainByHash.Put(prevMainData.Id, prevMainData)

		c.cleanup(minerData.Height)

		minerData.TimeReceived = time.Now()
		c.tipMinerData.Store(minerData)

		c.updateMedianTimestamp()

		utils.Logf("MainChain", "new miner data: major_version = %d, height = %d, prev_id = %s, seed_hash = %s, difficulty = %s", minerData.MajorVersion, minerData.Height, minerData.PrevId.String(), minerData.SeedHash.String(), minerData.Difficulty.StringNumeric())

		// Tx secret keys from all miners change every block, so cache can be cleared here
		if c.sidechain.PreCalcFinished() {
			c.sidechain.DerivationCache().Clear()
		}

		if c.p2pool.Started() {
			for h := minerData.Height; h > 0 && (h+BlockHeadersRequired) > minerData.Height; h-- {
				if d, ok := c.mainchainByHeight.Get(h); !ok || d.Difficulty.Equals(types.ZeroDifficulty) {
					utils.Logf("MainChain", "Main chain data for height = %d is missing, requesting from monerod again", h)
					missingHeights = append(missingHeights, h)
				}
			}
		}
	}()

	c.p2pool.UpdateMinerData(minerData)

	var wg sync.WaitGroup
	for _, h := range missingHeights {
		wg.Add(1)
		go func(height uint64) {
			wg.Done()
			if err := c.getBlockHeader(height); err != nil {
				utils.Errorf("MainChain", "%s", err)
			}
		}(h)
	}
	wg.Wait()

	c.updateTip()

}

func (c *MainChain) getBlockHeader(height uint64) error {
	if header, err := c.p2pool.ClientRPC().GetBlockHeaderByHeight(height, c.p2pool.Context()); err != nil {
		return fmt.Errorf("couldn't download block header for height %d: %s", height, err)
	} else {
		c.HandleMainHeader(&mainblock.Header{
			MajorVersion: uint8(header.BlockHeader.MajorVersion),
			MinorVersion: uint8(header.BlockHeader.MinorVersion),
			Timestamp:    uint64(header.BlockHeader.Timestamp),
			PreviousId:   header.BlockHeader.PrevHash,
			Height:       header.BlockHeader.Height,
			Nonce:        uint32(header.BlockHeader.Nonce),
			Reward:       header.BlockHeader.Reward,
			Id:           header.BlockHeader.Hash,
			Difficulty:   types.NewDifficulty(header.BlockHeader.Difficulty, header.BlockHeader.DifficultyTop64),
		})
	}

	return nil
}
