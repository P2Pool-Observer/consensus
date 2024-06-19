package merge_mining

import "git.gammaspectra.live/P2Pool/consensus/v4/types"

type AuxiliaryJob struct {
	Hash       types.Hash       `json:"aux_hash"`
	Blob       types.Bytes      `json:"aux_blob"`
	Difficulty types.Difficulty `json:"aux_diff"`
}
