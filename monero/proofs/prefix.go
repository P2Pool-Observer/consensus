package proofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TxPrefixHash(txId types.Hash, message string) types.Hash {
	return crypto.Keccak256Var(txId[:], []byte(message))
}
