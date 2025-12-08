//go:build !(amd64 || arm64) || purego

package cryptonight

func aes_rounds(state *[16]uint64, roundKeys *[aesRounds * 4]uint32) {
	aes_rounds_generic(state, roundKeys)
}

func aes_single_round(dst, src *[2]uint64, roundKey *[2]uint64) {
	aes_single_round_generic(dst, src, roundKey)
}
