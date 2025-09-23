package sidechain

import (
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/consensus/v4/utils"
)

type MergeMiningExtra []MergeMiningExtraData

var ExtraChainKeySubaddressViewPub = crypto.Keccak256Single([]byte("subaddress_viewpub"))

func (d MergeMiningExtra) Sort() {
	slices.SortStableFunc(d, func(a, b MergeMiningExtraData) int {
		return a.ChainId.Compare(b.ChainId)
	})
}

func (d MergeMiningExtra) Merge(other MergeMiningExtra) MergeMiningExtra {
	buf := append(d, other...)
	buf.Sort()
	return slices.CompactFunc(buf, func(data MergeMiningExtraData, data2 MergeMiningExtraData) bool {
		return data.ChainId == data2.ChainId
	})
}

func (d MergeMiningExtra) Get(chainId types.Hash) ([]byte, bool) {
	for _, e := range d {
		if e.ChainId == chainId {
			return e.Data, true
		}
	}
	return nil, false
}

func (d MergeMiningExtra) Set(chainId types.Hash, data []byte) MergeMiningExtra {
	for i, e := range d {
		if e.ChainId == chainId {
			d[i].Data = data
			return d
		}
	}

	newSlice := append(d, MergeMiningExtraData{
		ChainId: chainId,
		Data:    data,
	})

	d.Sort()

	return newSlice
}

func (d MergeMiningExtra) BufferLength() (size int) {
	for i := range d {
		size += d[i].BufferLength()
	}
	return size + utils.UVarInt64Size(len(d))
}

type MergeMiningExtraData struct {
	ChainId types.Hash  `json:"chain_id"`
	Data    types.Bytes `json:"data,omitempty"`
}

func (d MergeMiningExtraData) BufferLength() (size int) {
	return types.HashSize + utils.UVarInt64Size(len(d.Data)) + len(d.Data)
}
