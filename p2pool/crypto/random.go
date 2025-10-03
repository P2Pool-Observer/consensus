package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
)

var transactionPrivateKeySeedDomain = append([]byte("tx_key_seed"), 0)
var transactionPrivateKeyDomain = []byte("tx_secret_key")
var transactionRandomDomain = []byte("tx_random")

func CalculateTransactionPrivateKeySeed(main, side []byte) (result types.Hash) {
	h := crypto.GetKeccak256Hasher()
	defer crypto.PutKeccak256Hasher(h)
	_, _ = h.Write(transactionPrivateKeySeedDomain)
	_, _ = h.Write(main)
	_, _ = h.Write(side)
	crypto.HashFastSum(h, result[:])

	return result
}

func GetDeterministicTransactionPrivateKey(seed, previousMoneroId types.Hash) crypto.PrivateKey {
	/*
		Current deterministic key issues
		* This Deterministic private key changes too ofter, and does not fit full purpose (prevent knowledge of private keys on Coinbase without observing of sidechains).
		* It is shared across same miners on different p2pool sidechains, it does not contain Consensus Id.
		* It depends on weak sidechain historic data, but you can obtain public keys in other means.
		* A large cache must be kept containing entries for each miner in PPLNS window, for each Coinbase output. This cache is wiped when a new Monero block is found.
		* A counter is increased until the resulting hash fits the rules on deterministic scalar generation.
		* An external observer (who only observes the Monero chain) can guess the coinbase private key if they have a list of probable P2Pool miners, across all sidechains.

		k = H("tx_secret_key" | SpendPublicKey | PreviousMoneroId | uint32[counter])

	*/

	var entropy [13 + types.HashSize + types.HashSize + (4 /*pre-allocate uint32 for counter*/)]byte
	copy(entropy[:], transactionPrivateKeyDomain)
	copy(entropy[13:], seed[:])
	copy(entropy[13+types.HashSize:], previousMoneroId[:])
	return crypto.PrivateKeyFromScalar(crypto.DeterministicScalar(entropy[:13+types.HashSize+types.HashSize]))
}

// GetDeterministicCarrotOutputRandomness
// TODO: proper
func GetDeterministicCarrotOutputRandomness(seed types.Hash, blockIndex uint64, spendPub, viewPub *crypto.PublicKeyBytes) (out [monero.JanusAnchorSize]byte) {
	var entropy [9 + types.HashSize + 8 + crypto.PublicKeySize*2]byte
	copy(entropy[:], transactionRandomDomain)
	copy(entropy[9:], seed[:])
	binary.LittleEndian.PutUint64(entropy[9+types.HashSize:], blockIndex)
	copy(entropy[9+types.HashSize+8:], spendPub[:])
	copy(entropy[9+types.HashSize+8+crypto.PublicKeySize:], viewPub[:])
	h := crypto.Keccak256(entropy[:])
	copy(out[:], h[:])
	return out
}
