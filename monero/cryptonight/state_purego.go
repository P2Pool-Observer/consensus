//go:build purego

package cryptonight

// State Cryptonight state, to reuse between hashes. Not thread-safe.
type State struct {
	scratchpad  [ScratchpadSize / 8]uint64
	keccakState [25]uint64
	_           [8]byte // padded to keep 64-byte align (0x2000d0)

	blocks    [16]uint64            // temporary chunk/pointer of data
	roundKeys [aesRounds * 4]uint32 // 10 rounds, instead of 14 as in standard AES-256
	_         [8]byte               // padded to keep 16-byte align

	_                  [64]byte // prevents false sharing of r4 - r8
	r4, r5, r6, r7, r8 uint32
	_                  [16 - 4]byte // padded to keep 16-byte align

	// ops cached program, regenerated when codeHeight changes
	ops        [V4_NUM_INSTRUCTIONS_MAX + 1]op
	codeHeight uint64
}
