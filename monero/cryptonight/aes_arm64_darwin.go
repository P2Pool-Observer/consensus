//go:build darwin && arm64 && !purego

package cryptonight

//go:nosplit
//go:noescape
func aes_rounds_internal(state *[2]uint64, roundKeys *[aesRounds * 4]uint32)

//go:nosplit
//go:noescape
func aes_single_round_internal(dst, src *[2]uint64, roundKey *[2]uint64)

// Assume all M1+ have AES
//
// See https://github.com/golang/go/issues/43046
// See https://github.com/golang/go/commit/c15593197453b8bf90fc3a9080ba2afeaf7934ea

//go:nosplit
func aes_rounds(state *[2]uint64, roundKeys *[aesRounds * 4]uint32) {
	aes_rounds_internal(state, roundKeys)
}

//go:nosplit
func aes_single_round(dst, src *[2]uint64, roundKey *[2]uint64) {
	aes_single_round_internal(dst, src, roundKey)
}
