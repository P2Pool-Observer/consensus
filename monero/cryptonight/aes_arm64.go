//go:build !darwin && arm64 && !purego

package cryptonight

import "golang.org/x/sys/cpu"

//go:nosplit
//go:noescape
func aes_rounds_internal(state *[2]uint64, roundKeys *[aesRounds * 4]uint32)

//go:nosplit
//go:noescape
func aes_single_round_internal(dst, src *[2]uint64, roundKey *[2]uint64)

//go:nosplit
func aes_rounds(state *[2]uint64, roundKeys *[aesRounds * 4]uint32) {
	if cpu.ARM64.HasAES {
		aes_rounds_internal(state, roundKeys)
		return
	}
	aes_rounds_generic(state, roundKeys)
}

//go:nosplit
func aes_single_round(dst, src *[2]uint64, roundKey *[2]uint64) {
	if cpu.ARM64.HasAES {
		aes_single_round_internal(dst, src, roundKey)
		return
	}
	aes_single_round_generic(dst, src, roundKey)
}
