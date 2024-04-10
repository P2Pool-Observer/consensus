package sidechain

import (
	"fmt"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero"
)

// List of historical hardforks that p2pool networks went through
// These are not kept in later p2pool releases.
// If you ever find yourself back in time with a new p2pool release, it will start at its latest supported
var p2poolMainNetHardForks = []monero.HardFork{
	{uint8(ShareVersion_V1), 0, 0, 0},
	// p2pool hardforks at 2023-03-18 21:00 UTC
	{uint8(ShareVersion_V2), 0, 0, 1679173200},
}

var p2poolTestNetHardForks = []monero.HardFork{
	{uint8(ShareVersion_V1), 0, 0, 0},
	// p2pool hardforks at 2023-01-23 21:00 UTC
	{uint8(ShareVersion_V2), 0, 0, 1674507600},
	//alternate hardfork at 2023-03-07 20:00 UTC 1678219200
	//{uint8(ShareVersion_V2), 0, 0, 1678219200},
}

var p2poolStageNetHardForks = []monero.HardFork{
	//always latest version
	{p2poolMainNetHardForks[len(p2poolMainNetHardForks)-1].Version, 0, 0, 0},
}

type ShareVersion uint8

func (v ShareVersion) String() string {
	switch v {
	case ShareVersion_None:
		return "none"
	default:
		return fmt.Sprintf("v%d", v)
	}
}

const (
	ShareVersion_None = ShareVersion(iota)

	// ShareVersion_V1 Initial version. Had optional deterministic private keys, and signaling of support of V2 on extra nonce
	ShareVersion_V1

	// ShareVersion_V2 Enforced deterministic private keys (and made more efficient)
	// Removed the private key field as it's implied, replaced with private key seed
	// Added extra fields to side data with extra nonces and random data, and carries software id and version
	// PPLNS Window weight is now dynamic up to minimum of mainchain difficulty * 2
	// Coinbase outputs are shuffled with a deterministic random method to mask output order on Monero
	ShareVersion_V2

	// ShareVersion_V3 Tentative future version with merge mining support.
	// Fixed Merge Mining Tag encoding, replace template id with a proper merkle root and other auxiliary data
	// Merkle proof added on side data
	// Template Id is now included as part of pruned blocks
	ShareVersion_V3
)

// P2PoolShareVersion
// Different miners can have different timestamps,
// so a temporary mix of old and new blocks is allowed
func P2PoolShareVersion(consensus *Consensus, timestamp uint64) ShareVersion {
	hardForks := consensus.HardForks

	if len(hardForks) == 0 {
		return ShareVersion_None
	}

	result := hardForks[0].Version

	for _, f := range hardForks[1:] {
		if timestamp < f.Time {
			break
		}
		result = f.Version
	}
	return ShareVersion(result)
}
