package api

import (
	"bytes"
	"errors"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/block"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v3/p2pool/sidechain"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v3/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/utils"
	"github.com/hashicorp/golang-lru/v2"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"
)

type P2PoolApi struct {
	Host                    string
	Client                  *http.Client
	consensus               atomic.Pointer[sidechain.Consensus]
	derivationCache         sidechain.DerivationCacheInterface
	difficultyByHeightCache *lru.Cache[uint64, types.Difficulty]
}

func NewP2PoolApi(host string) *P2PoolApi {
	cache, err := lru.New[uint64, types.Difficulty](1024)
	if err != nil {
		return nil
	}
	return &P2PoolApi{
		Host: host,
		Client: &http.Client{
			Timeout: time.Second * 15,
		},
		derivationCache:         sidechain.NewDerivationLRUCache(),
		difficultyByHeightCache: cache,
	}
}

func (p *P2PoolApi) WaitSync() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panicked")
		}
	}()
	status := p.Status()
	for ; p == nil || !p.Status().Synchronized; status = p.Status() {
		if p == nil {
			utils.Logf("API", "Not synchronized (nil), waiting five seconds")
		} else {
			utils.Logf("API", "Not synchronized (height %d, id %s, blocks %d), waiting five seconds", status.Height, status.Id, status.Blocks)
		}
		time.Sleep(time.Second * 5)
	}
	utils.Logf("API", "SYNCHRONIZED (height %d, id %s, blocks %d)", status.Height, status.Id, status.Blocks)
	utils.Logf("API", "Consensus id = %s\n", p.Consensus().Id)
	return nil
}

func (p *P2PoolApi) WaitSyncStart() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panicked")
		}
	}()
	status := p.Status()
	for ; p == nil || !p.Status().Synchronized; status = p.Status() {
		if p == nil {
			utils.Logf("API", "Not synchronized (nil), waiting one seconds")
		} else {
			utils.Logf("API", "Not synchronized (height %d, id %s, blocks %d)", status.Height, status.Id, status.Blocks)
			break
		}
		time.Sleep(time.Second * 1)
	}
	if status.Synchronized {
		utils.Logf("API", "SYNCHRONIZED (height %d, id %s, blocks %d)", status.Height, status.Id, status.Blocks)
	}
	utils.Logf("API", "Consensus id = %s\n", p.Consensus().Id)
	return nil
}

func (p *P2PoolApi) InsertAlternate(b *sidechain.PoolBlock) {
	buf, _ := b.MarshalBinary()
	uri, _ := url.Parse(p.Host + "/archive/insert_alternate")
	response, err := p.Client.Do(&http.Request{
		Method: "POST",
		URL:    uri,
		Body:   io.NopCloser(bytes.NewReader(buf)),
	})
	if err != nil {
		return
	}
	defer response.Body.Close()
}

func (p *P2PoolApi) LightByMainId(id types.Hash) *sidechain.PoolBlock {
	if response, err := p.Client.Get(p.Host + "/archive/light_block_by_main_id/" + id.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			b := &sidechain.PoolBlock{}

			if err = utils.UnmarshalJSON(buf, &b); err != nil || b.ShareVersion() == sidechain.ShareVersion_None {
				return nil
			}

			return b
		}
	}
}

func (p *P2PoolApi) LightByMainIdWithHint(id, templateIdHint types.Hash) *sidechain.PoolBlock {
	if response, err := p.Client.Get(p.Host + "/archive/light_block_by_main_id/" + id.String() + "?templateIdHint=" + templateIdHint.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			b := &sidechain.PoolBlock{}

			if err = utils.UnmarshalJSON(buf, &b); err != nil || b.ShareVersion() == sidechain.ShareVersion_None {
				return nil
			}

			return b
		}
	}
}

func (p *P2PoolApi) ByMainId(id types.Hash) *sidechain.PoolBlock {
	if response, err := p.Client.Get(p.Host + "/archive/block_by_main_id/" + id.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result p2pooltypes.P2PoolBinaryBlockResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil || result.Version == 0 {
				return nil
			}

			b := &sidechain.PoolBlock{}
			if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, result.Blob); err != nil || int(b.ShareVersion()) != result.Version {
				return nil
			}
			return b
		}
	}
}

func (p *P2PoolApi) ByMainIdWithHint(id, templateIdHint types.Hash) *sidechain.PoolBlock {
	if response, err := p.Client.Get(p.Host + "/archive/block_by_main_id/" + id.String() + "?templateIdHint=" + templateIdHint.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result p2pooltypes.P2PoolBinaryBlockResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil || result.Version == 0 {
				return nil
			}

			b := &sidechain.PoolBlock{}
			if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, result.Blob); err != nil || int(b.ShareVersion()) != result.Version {
				return nil
			}
			return b
		}
	}
}

func (p *P2PoolApi) LightByTemplateId(id types.Hash) sidechain.UniquePoolBlockSlice {
	if response, err := p.Client.Get(p.Host + "/archive/light_blocks_by_template_id/" + id.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result sidechain.UniquePoolBlockSlice

			if err = utils.UnmarshalJSON(buf, &result); err != nil || len(result) == 0 {
				return nil
			}

			return result
		}
	}
}

func (p *P2PoolApi) ByTemplateId(id types.Hash) *sidechain.PoolBlock {
	if response, err := p.Client.Get(p.Host + "/sidechain/block_by_template_id/" + id.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result p2pooltypes.P2PoolBinaryBlockResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			} else if result.Version == 0 {
				// Fallback into archive
				if response, err := p.Client.Get(p.Host + "/archive/blocks_by_template_id/" + id.String()); err != nil {
					return nil
				} else {
					defer response.Body.Close()

					if buf, err := io.ReadAll(response.Body); err != nil {
						return nil
					} else {
						var result []p2pooltypes.P2PoolBinaryBlockResult

						if err = utils.UnmarshalJSON(buf, &result); err != nil || len(result) == 0 {
							return nil
						}

						for _, r := range result {
							//Get first block that matches
							if r.Version == 0 {
								continue
							}
							b := &sidechain.PoolBlock{}
							if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil || int(b.ShareVersion()) != r.Version {
								continue
							}
							return b
						}
						return nil
					}
				}
			}

			b := &sidechain.PoolBlock{}
			if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, result.Blob); err != nil {
				return nil
			}
			return b
		}
	}
}

func (p *P2PoolApi) LightBySideHeight(height uint64) sidechain.UniquePoolBlockSlice {
	if response, err := p.Client.Get(p.Host + "/archive/light_blocks_by_side_height/" + strconv.FormatUint(height, 10)); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result sidechain.UniquePoolBlockSlice

			if err = utils.UnmarshalJSON(buf, &result); err != nil || len(result) == 0 {
				return nil
			}

			return result
		}
	}
}

func (p *P2PoolApi) BySideHeight(height uint64) sidechain.UniquePoolBlockSlice {
	if response, err := p.Client.Get(p.Host + "/sidechain/blocks_by_height/" + strconv.FormatUint(height, 10)); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result []p2pooltypes.P2PoolBinaryBlockResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			} else if len(result) == 0 {
				// Fallback into archive
				if response, err := p.Client.Get(p.Host + "/archive/blocks_by_side_height/" + strconv.FormatUint(height, 10)); err != nil {
					return nil
				} else {
					defer response.Body.Close()

					if buf, err := io.ReadAll(response.Body); err != nil {
						return nil
					} else {
						var result []p2pooltypes.P2PoolBinaryBlockResult

						if err = utils.UnmarshalJSON(buf, &result); err != nil || len(result) == 0 {
							return nil
						}

						results := make([]*sidechain.PoolBlock, 0, len(result))
						for _, r := range result {
							if r.Version == 0 {
								return nil
							}
							b := &sidechain.PoolBlock{}
							if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
								return nil
							}
							results = append(results, b)
						}
						return results
					}
				}
			}

			results := make([]*sidechain.PoolBlock, 0, len(result))
			for _, r := range result {
				if r.Version == 0 {
					return nil
				}
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil
				}
				results = append(results, b)
			}
			return results
		}
	}
}

func (p *P2PoolApi) LightByMainHeight(height uint64) sidechain.UniquePoolBlockSlice {
	if response, err := p.Client.Get(p.Host + "/archive/light_blocks_by_main_height/" + strconv.FormatUint(height, 10)); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result sidechain.UniquePoolBlockSlice

			if err = utils.UnmarshalJSON(buf, &result); err != nil || len(result) == 0 {
				return nil
			}

			return result
		}
	}
}

func (p *P2PoolApi) ByMainHeight(height uint64) sidechain.UniquePoolBlockSlice {
	if response, err := p.Client.Get(p.Host + "/archive/blocks_by_main_height/" + strconv.FormatUint(height, 10)); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result []p2pooltypes.P2PoolBinaryBlockResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil || len(result) == 0 {
				return nil
			}

			results := make([]*sidechain.PoolBlock, 0, len(result))
			for _, r := range result {
				if r.Version == 0 {
					return nil
				}
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil
				}
				results = append(results, b)
			}
			return results
		}
	}
}

func (p *P2PoolApi) DifficultyByHeight(height uint64) types.Difficulty {
	if v := p.difficultyByHeightCache.Get(height); v == nil {
		if diff := p.MainDifficultyByHeight(height); diff != types.ZeroDifficulty {
			p.difficultyByHeightCache.Set(height, diff)
			return diff
		}
		return types.ZeroDifficulty
	} else {
		return *v
	}
}

func (p *P2PoolApi) SeedByHeight(height uint64) types.Hash {
	seedHeight := randomx.SeedHeight(height)
	if v := p.MainHeaderByHeight(seedHeight); v != nil {
		return v.Id
	}
	return types.ZeroHash
}

func (p *P2PoolApi) PeerList() []byte {
	if response, err := p.Client.Get(p.Host + "/server/peerlist"); err != nil {
		return nil
	} else {
		defer response.Body.Close()
		buf, err := io.ReadAll(response.Body)
		if err == nil {
			return buf
		}
	}

	return nil
}

func (p *P2PoolApi) ConnectionCheck(addrPort netip.AddrPort) *p2pooltypes.P2PoolConnectionCheckInformation[*sidechain.PoolBlock] {
	if response, err := p.Client.Get(p.Host + "/server/connection_check/" + addrPort.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result p2pooltypes.P2PoolConnectionCheckInformation[*sidechain.PoolBlock]

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			}

			return &result
		}
	}
}

func (p *P2PoolApi) MinerData() *p2pooltypes.MinerData {
	if response, err := p.Client.Get(p.Host + "/mainchain/miner_data"); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result p2pooltypes.MinerData

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			}

			return &result
		}
	}
}

func (p *P2PoolApi) MainTip() *block.Header {
	if response, err := p.Client.Get(p.Host + "/mainchain/tip"); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result block.Header

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			}

			return &result
		}
	}
}

func (p *P2PoolApi) MainHeaderById(id types.Hash) *block.Header {
	if response, err := p.Client.Get(p.Host + "/mainchain/header_by_id/" + id.String()); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result block.Header

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			}

			return &result
		}
	}
}

func (p *P2PoolApi) MainHeaderByHeight(height uint64) *block.Header {
	if response, err := p.Client.Get(p.Host + "/mainchain/header_by_height/" + strconv.FormatUint(height, 10)); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result block.Header

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			}

			return &result
		}
	}
}

func (p *P2PoolApi) MainDifficultyByHeight(height uint64) types.Difficulty {
	if response, err := p.Client.Get(p.Host + "/mainchain/difficulty_by_height/" + strconv.FormatUint(height, 10)); err != nil {
		return types.ZeroDifficulty
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return types.ZeroDifficulty
		} else {
			var result types.Difficulty

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return types.ZeroDifficulty
			}

			return result
		}
	}
}

func (p *P2PoolApi) StateFromTemplateId(id types.Hash) (chain, uncles sidechain.UniquePoolBlockSlice) {
	if response, err := p.Client.Get(p.Host + "/sidechain/state/" + id.String()); err != nil {
		return nil, nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil, nil
		} else {
			var result p2pooltypes.P2PoolSideChainStateResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil, nil
			}

			chain = make([]*sidechain.PoolBlock, 0, len(result.Chain))
			uncles = make([]*sidechain.PoolBlock, 0, len(result.Uncles))

			for _, r := range result.Chain {
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil, nil
				}
				chain = append(chain, b)
			}

			for _, r := range result.Uncles {
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil, nil
				}
				uncles = append(uncles, b)
			}

			return chain, uncles
		}
	}
}

func (p *P2PoolApi) WindowFromTemplateId(id types.Hash) (chain, uncles sidechain.UniquePoolBlockSlice) {
	if response, err := p.Client.Get(p.Host + "/archive/window_from_template_id/" + id.String()); err != nil {
		return nil, nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil, nil
		} else {
			var result p2pooltypes.P2PoolSideChainStateResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil, nil
			}

			chain = make([]*sidechain.PoolBlock, 0, len(result.Chain))
			uncles = make([]*sidechain.PoolBlock, 0, len(result.Uncles))

			for _, r := range result.Chain {
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil, nil
				}
				chain = append(chain, b)
			}

			for _, r := range result.Uncles {
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil, nil
				}
				uncles = append(uncles, b)
			}

			return chain, uncles
		}
	}
}

func (p *P2PoolApi) StateFromTip() (chain, uncles sidechain.UniquePoolBlockSlice) {
	if response, err := p.Client.Get(p.Host + "/sidechain/state/tip"); err != nil {
		return nil, nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil, nil
		} else {
			var result p2pooltypes.P2PoolSideChainStateResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil, nil
			}

			chain = make([]*sidechain.PoolBlock, 0, len(result.Chain))
			uncles = make([]*sidechain.PoolBlock, 0, len(result.Uncles))

			for _, r := range result.Chain {
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil, nil
				}
				chain = append(chain, b)
			}

			for _, r := range result.Uncles {
				b := &sidechain.PoolBlock{}
				if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, r.Blob); err != nil {
					return nil, nil
				}
				uncles = append(uncles, b)
			}

			return chain, uncles
		}
	}
}

func (p *P2PoolApi) Tip() *sidechain.PoolBlock {
	if response, err := p.Client.Get(p.Host + "/sidechain/tip"); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			var result p2pooltypes.P2PoolBinaryBlockResult

			if err = utils.UnmarshalJSON(buf, &result); err != nil {
				return nil
			}

			if result.Version == 0 {
				return nil
			}
			b := &sidechain.PoolBlock{}
			if err = b.UnmarshalBinary(p.Consensus(), p.derivationCache, result.Blob); err != nil {
				return nil
			}
			return b
		}
	}
}

func (p *P2PoolApi) getConsensus() *sidechain.Consensus {
	if response, err := p.Client.Get(p.Host + "/sidechain/consensus"); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			c, _ := sidechain.NewConsensusFromJSON(buf)

			return c
		}
	}
}

func (p *P2PoolApi) Consensus() *sidechain.Consensus {
	if c := p.consensus.Load(); c == nil {
		if c = p.getConsensus(); c != nil {
			p.consensus.Store(c)
		}
		return c
	} else {
		return c
	}
}

func (p *P2PoolApi) Status() *p2pooltypes.P2PoolSideChainStatusResult {
	if response, err := p.Client.Get(p.Host + "/sidechain/status"); err != nil {
		return nil
	} else {
		defer response.Body.Close()

		if buf, err := io.ReadAll(response.Body); err != nil {
			return nil
		} else {
			result := &p2pooltypes.P2PoolSideChainStatusResult{}

			if err = utils.UnmarshalJSON(buf, result); err != nil {
				return nil
			}

			return result
		}
	}
}
