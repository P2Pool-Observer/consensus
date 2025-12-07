package cryptonight

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"golang.org/x/sys/cpu"
)

// ScratchpadSize 2 MiB scratchpad for memhard loop
const ScratchpadSize = 2 * 1024 * 1024

// State Cryptonight state, to reuse between hashes. Not thread-safe.
type State struct {
	scratchpad  [ScratchpadSize / 8]uint64
	keccakState [25]uint64
	_           [8]byte // padded to keep 16-byte align (0x2000d0)

	blocks    [16]uint64            // temporary chunk/pointer of data
	roundKeys [aesRounds * 4]uint32 // 10 rounds, instead of 14 as in standard AES-256
	_         [8]byte               // padded to keep 16-byte align

	_                  cpu.CacheLinePad // prevents false sharing of r4 - r8
	r4, r5, r6, r7, r8 uint32
	_                  [16 - 4]byte // padded to keep 16-byte align

	// ops cached program, regenerated when codeHeight changes
	ops        [V4_NUM_INSTRUCTIONS_MAX + 1]op
	codeHeight uint64
}

func (cn *State) SumR(data []byte, height uint64, prehashed bool) types.Hash {
	return cn.sum_v2_r(data, R, height, prehashed)
}

// Sum Computes the hash of <data> (which consists of <length> bytes), returning the
// hash in <hash>.  The CryptoNight hash operates by first using Keccak 1600,
// the 1600 bit variant of the Keccak hash used in SHA-3, to create a 200 byte
// buffer of pseudorandom data by hashing the supplied data.  It then uses this
// random data to fill a large 2MB buffer with pseudorandom data by iteratively
// encrypting it using 10 rounds of AES per entry.  After this initialization,
// it executes 524,288 rounds of mixing through the random 2MB buffer using
// AES (typically provided in hardware on modern CPUs) and a 64 bit multiply.
// Finally, it re-mixes this large buffer back into
// the 200 byte "text" buffer, and then hashes this buffer using one of four
// pseudorandomly selected hash functions (Blake, Groestl, JH, or Skein)
// to populate the output.
//
// The 2MB buffer and choice of functions for mixing are designed to make the
// algorithm "CPU-friendly" (and thus, reduce the advantage of GPU, FPGA,
// or ASIC-based implementations):  the functions used are fast on modern
// CPUs, and the 2MB size matches the typical amount of L3 cache available per
// core on 2013-era CPUs.  When available, this implementation will use hardware
// AES support on x86 CPUs.
//
// A diagram of the inner loop of this function can be found at
// https://www.cs.cmu.edu/~dga/crypto/xmr/cryptonight.png
func (cn *State) Sum(data []byte, variant Variant, prehashed bool) types.Hash {
	if variant == V0 || variant == V1 {
		return cn.sum_v0_v1(data, variant, prehashed)
	}
	return cn.sum_v2_r(data, variant, 0, prehashed)
}
