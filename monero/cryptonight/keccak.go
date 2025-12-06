package cryptonight

import (
	_ "unsafe"

	_ "golang.org/x/crypto/sha3" //nolint:depguard
)

//go:noescape
//go:linkname keccakF1600 golang.org/x/crypto/sha3.keccakF1600
func keccakF1600(a *[25]uint64)
