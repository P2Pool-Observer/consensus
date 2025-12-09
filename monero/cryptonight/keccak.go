package cryptonight

import (
	"hash"
	"unsafe"

	_ "golang.org/x/crypto/sha3" //nolint:depguard
)

//go:noescape
//go:linkname keccakF1600 golang.org/x/crypto/sha3.keccakF1600
func keccakF1600(a *[25]uint64)

type genericInterface struct {
	_type uintptr
	data  unsafe.Pointer
}
type keccakState struct {
	a         [1600 / 8]byte
	n, rate   int
	dsbyte    byte
	outputLen int
	state     int
}

func keccakStatePtr(h hash.Hash) *[1600 / 8]byte {
	// extremely unsafe
	// read eface/iface ptr to get underlying state field
	// #nosec 103 -- specifically checked structure
	state := (*keccakState)((*genericInterface)(unsafe.Pointer(&h)).data)
	return &state.a
}
