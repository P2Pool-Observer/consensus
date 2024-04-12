//go:build !cgo || disable_randomx_library

package randomx

import (
	"bytes"
	"crypto/subtle"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"git.gammaspectra.live/P2Pool/go-randomx/v2"
	"runtime"
	"sync"
	"unsafe"
)

type hasher struct {
	cache *randomx.Randomx_Cache
	lock  sync.Mutex
	flags []Flag

	key []byte
}

func ConsensusHash(buf []byte) types.Hash {
	cache := randomx.Randomx_alloc_cache(0)
	cache.Init(buf)

	scratchpad := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(cache.Blocks))), len(cache.Blocks)*len(cache.Blocks[0])*int(unsafe.Sizeof(uint64(0))))
	defer runtime.KeepAlive(cache)

	// Intentionally not a power of 2
	const ScratchpadSize = 1009

	const RandomxArgonMemory = 262144
	n := RandomxArgonMemory * 1024

	const Vec128Size = 128 / 8

	type Vec128 [Vec128Size]byte

	cachePtr := scratchpad[ScratchpadSize*Vec128Size:]
	scratchpadTopPtr := scratchpad[:ScratchpadSize*Vec128Size]
	for i := ScratchpadSize * Vec128Size; i < n; i += ScratchpadSize * Vec128Size {
		stride := ScratchpadSize * Vec128Size
		if stride > len(cachePtr) {
			stride = len(cachePtr)
		}
		subtle.XORBytes(scratchpadTopPtr, scratchpadTopPtr, cachePtr[:stride])
		cachePtr = cachePtr[stride:]
	}

	return crypto.Keccak256(scratchpadTopPtr)
}

func (h *hasher) OptionFlags(flags ...Flag) error {
	return nil
}
func (h *hasher) OptionNumberOfCachedStates(n int) error {
	return nil
}

func NewRandomX(n int, flags ...Flag) (Hasher, error) {
	return &hasher{
		flags: flags,
		cache: randomx.Randomx_alloc_cache(randomx.RANDOMX_FLAG_JIT),
	}, nil
}

func (h *hasher) Hash(key []byte, input []byte) (output types.Hash, err error) {
	vm := func() *randomx.VM {
		h.lock.Lock()
		defer h.lock.Unlock()

		if h.key == nil || bytes.Compare(h.key, key) != 0 {
			h.key = make([]byte, len(key))
			copy(h.key, key)

			h.cache.Init(h.key)
		}
		return h.cache.VM_Initialize()
	}()

	vm.CalculateHash(input, (*[32]byte)(&output))
	return
}

func (h *hasher) Close() {
	h.cache.Close()
}
