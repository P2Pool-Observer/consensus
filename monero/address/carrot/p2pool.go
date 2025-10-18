package carrot

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

const DomainSeparatorP2PoolDeterministicCarrotOutputRandomness = "P2Pool deterministic Carrot output randomness"

// GetP2PoolDeterministicCarrotOutputRandomness Used by P2Pool to fill the PaymentProposalV1.Randomness
// Seed is used as key
func GetP2PoolDeterministicCarrotOutputRandomness(hasher *blake2b.Digest, seed types.Hash, blockIndex uint64, spendPub, viewPub *crypto.PublicKeyBytes) (out [monero.JanusAnchorSize]byte) {
	inputContext := MakeCoinbaseInputContext(blockIndex)
	// a = H_16("..P2Pool..", seed, inputContext, j_s, j_v, nonce)

	var counter uint32
	var nonce [4]byte

	for {
		HashedTranscript(out[:], hasher, []byte(DomainSeparatorP2PoolDeterministicCarrotOutputRandomness), seed[:], inputContext[:], spendPub[:], viewPub[:], nonce[:])
		if out != [monero.JanusAnchorSize]byte{} {
			break
		}
		// ensure not zero
		counter++
		binary.LittleEndian.PutUint32(nonce[:], counter)
	}
	return out
}
