package sidechain

import (
	"context"
	"fmt"
	mainblock "git.gammaspectra.live/P2Pool/consensus/v4/monero/block"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v4/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"sync"
)

type FakeServer struct {
	consensus   *Consensus
	headersLock sync.Mutex
	headers     map[uint64]*mainblock.Header
	sidechain   *SideChain
}

func (s *FakeServer) Context() context.Context {
	return context.Background()
}

func (s *FakeServer) Consensus() *Consensus {
	return s.consensus
}

func (s *FakeServer) GetBlob(key []byte) (blob []byte, err error) {
	return nil, nil
}

func (s *FakeServer) SetBlob(key, blob []byte) (err error) {
	return nil
}

func (s *FakeServer) RemoveBlob(key []byte) (err error) {
	return nil
}

func (s *FakeServer) UpdateTip(tip *PoolBlock) {

}
func (s *FakeServer) Broadcast(block *PoolBlock) {

}
func (s *FakeServer) ClientRPC() *client.Client {
	return client.GetDefaultClient()
}
func (s *FakeServer) GetChainMainByHeight(height uint64) *ChainMain {
	return nil
}
func (s *FakeServer) GetChainMainByHash(hash types.Hash) *ChainMain {
	return nil
}
func (s *FakeServer) GetMinimalBlockHeaderByHeight(height uint64) *mainblock.Header {
	s.headersLock.Lock()
	defer s.headersLock.Unlock()
	if h, ok := s.headers[height]; ok {
		return h
	}
	if h, err := s.ClientRPC().GetBlockHeaderByHeight(height, context.Background()); err != nil {
		return nil
	} else {
		header := &mainblock.Header{
			MajorVersion: uint8(h.BlockHeader.MajorVersion),
			MinorVersion: uint8(h.BlockHeader.MinorVersion),
			Timestamp:    uint64(h.BlockHeader.Timestamp),
			PreviousId:   h.BlockHeader.PrevHash,
			Height:       h.BlockHeader.Height,
			Nonce:        uint32(h.BlockHeader.Nonce),
			Reward:       h.BlockHeader.Reward,
			Difficulty:   types.NewDifficulty(h.BlockHeader.Difficulty, h.BlockHeader.DifficultyTop64),
			Id:           h.BlockHeader.Hash,
		}
		s.headers[height] = header
		return header
	}
}

func (s *FakeServer) DownloadMinimalBlockHeaders(currentHeight uint64) error {
	// BlockHeadersRequired TODO: make this dynamic depending on PPLNS size
	const BlockHeadersRequired = 720

	var startHeight uint64
	if currentHeight > BlockHeadersRequired {
		startHeight = currentHeight - BlockHeadersRequired
	}

	if rangeResult, err := s.ClientRPC().GetBlockHeadersRangeResult(startHeight, currentHeight-1, s.Context()); err != nil {
		return fmt.Errorf("couldn't download block headers range for height %d to %d: %s", startHeight, currentHeight-1, err)
	} else {
		s.headersLock.Lock()
		defer s.headersLock.Unlock()

		for _, header := range rangeResult.Headers {
			s.headers[header.Height] = &mainblock.Header{
				MajorVersion: uint8(header.MajorVersion),
				MinorVersion: uint8(header.MinorVersion),
				Timestamp:    uint64(header.Timestamp),
				PreviousId:   header.PrevHash,
				Height:       header.Height,
				Nonce:        uint32(header.Nonce),
				Reward:       header.Reward,
				Id:           header.Hash,
				Difficulty:   types.NewDifficulty(header.Difficulty, header.DifficultyTop64),
			}
		}
		return nil
	}
}

func (s *FakeServer) GetMinimalBlockHeaderByHash(hash types.Hash) *mainblock.Header {
	return nil
}
func (s *FakeServer) GetDifficultyByHeight(height uint64) types.Difficulty {
	return s.GetMinimalBlockHeaderByHeight(height).Difficulty
}
func (s *FakeServer) UpdateBlockFound(data *ChainMain, block *PoolBlock) {

}
func (s *FakeServer) SubmitBlock(block *mainblock.Block) {

}
func (s *FakeServer) GetChainMainTip() *ChainMain {
	return nil
}
func (s *FakeServer) GetMinerDataTip() *p2pooltypes.MinerData {
	return nil
}
func (s *FakeServer) Store(block *PoolBlock) {

}
func (s *FakeServer) ClearCachedBlocks() {

}

func (s *FakeServer) SideChain() *SideChain {
	return s.sidechain
}

func GetFakeTestServer(consensus *Consensus) *FakeServer {
	s := &FakeServer{
		consensus: consensus,
		headers:   make(map[uint64]*mainblock.Header),
	}
	s.sidechain = NewSideChain(s)
	return s
}
