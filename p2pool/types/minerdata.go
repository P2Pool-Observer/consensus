package types

import (
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v5/p2pool/mempool"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type MinerData struct {
	MajorVersion          uint8            `json:"major_version"`
	MinorVersion          uint8            `json:"minor_version,omitempty"`
	Height                uint64           `json:"height"`
	PrevId                types.Hash       `json:"prev_id"`
	SeedHash              types.Hash       `json:"seed_hash"`
	Difficulty            types.Difficulty `json:"difficulty"`
	MedianWeight          uint64           `json:"median_weight"`
	AlreadyGeneratedCoins uint64           `json:"already_generated_coins"`
	MedianTimestamp       uint64           `json:"median_timestamp"`
	TxBacklog             mempool.Mempool  `json:"tx_backlog"`

	FCMPTreeLayers uint8      `json:"fcmp_pp_n_tree_layers,omitempty"`
	FCMPTreeRoot   types.Hash `json:"fcmp_pp_tree_root,omitempty"`

	TimeReceived time.Time `json:"time_received"`

	AuxiliaryChains []AuxiliaryChainData `json:"aux_chains,omitempty"`
	AuxiliaryNonce  uint32               `json:"aux_nonce,omitempty"`
}

type AuxiliaryChainData struct {
	UniqueId   types.Hash
	Data       types.Hash
	Difficulty types.Difficulty
}
