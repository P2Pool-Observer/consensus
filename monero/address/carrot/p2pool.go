package carrot

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

const DomainSeparatorP2PoolDeterministicCarrotOutputRandomness = "P2Pool deterministic Carrot output randomness"

// GetP2PoolDeterministicCarrotOutputRandomness Used by P2Pool to fill the PaymentProposalV1.Randomness for CoinbaseEnoteV1
// Seed is used as "secret" sidechain key, in addition of the usual carrot input context.
// This is unique per P2Pool sidechain and block context, and regularly rotates.
//
// It is important for each individual output to not share Randomness with each other.
// Otherwise, given outputs a, b with encrypted Randomness ER_a = R_a ^ K_a, ER_b = R_b ^ K_b,
// with R_a = R_b would let passive lookers learn ER_a ^ ER_b = K_a ^ K_b
// This issue would get worse as more XOR cancellation is possible.
//
// While extremely unlikely to happen (16 zero bytes), this function ensures a non-zero output for the Randomness field by using a nonce counter that starts at 0.
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
