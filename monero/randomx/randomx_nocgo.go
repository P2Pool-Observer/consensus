//go:build !cgo || !enable_randomx_library || purego

package randomx

import (
	"bytes"
	"errors"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/utils"
	"git.gammaspectra.live/P2Pool/go-randomx/v3"
	fasthex "github.com/tmthrgd/go-hex"
	"runtime"
	"slices"
	"sync"
	"unsafe"
)

type hasherCollection struct {
	lock  sync.RWMutex
	index int
	flags []Flag
	cache []*hasherState
}

func (h *hasherCollection) Hash(key []byte, input []byte) (types.Hash, error) {
	if hash, err := func() (types.Hash, error) {
		h.lock.RLock()
		defer h.lock.RUnlock()
		for _, c := range h.cache {
			if len(c.key) > 0 && bytes.Compare(c.key, key) == 0 {
				return c.Hash(input), nil
			}
		}

		return types.ZeroHash, errors.New("no hasher")
	}(); err == nil && hash != types.ZeroHash {
		return hash, nil
	} else {
		h.lock.Lock()
		defer h.lock.Unlock()
		index := h.index
		h.index = (h.index + 1) % len(h.cache)
		if err = h.cache[index].Init(key); err != nil {
			return types.ZeroHash, err
		}
		return h.cache[index].Hash(input), nil
	}
}

func (h *hasherCollection) initStates(size int) (err error) {
	for _, c := range h.cache {
		c.Close()
	}
	h.cache = make([]*hasherState, size)
	for i := range h.cache {
		if h.cache[i], err = newRandomXState(h.flags...); err != nil {
			return err
		}
	}
	return nil
}

func (h *hasherCollection) OptionFlags(flags ...Flag) error {
	h.lock.Lock()
	defer h.lock.Unlock()
	if slices.Compare(h.flags, flags) != 0 {
		h.flags = flags
		return h.initStates(len(h.cache))
	}
	return nil
}
func (h *hasherCollection) OptionNumberOfCachedStates(n int) error {
	h.lock.Lock()
	defer h.lock.Unlock()
	if len(h.cache) != n {
		return h.initStates(n)
	}
	return nil
}

func (h *hasherCollection) Close() {
	h.lock.Lock()
	defer h.lock.Unlock()
	for _, c := range h.cache {
		c.Close()
	}
}

type hasherState struct {
	lock    sync.Mutex
	cache   *randomx.Cache
	dataset randomx.Dataset
	vm      *randomx.VM
	flags   uint64
	key     []byte
}

func ConsensusHash(buf []byte) types.Hash {
	cache := randomx.NewCache(0)
	defer cache.Close()

	cache.Init(buf)

	scratchpad := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(cache.Blocks))), len(cache.Blocks)*len(cache.Blocks[0])*int(unsafe.Sizeof(uint64(0))))
	defer runtime.KeepAlive(cache)

	return consensusHash(scratchpad)
}

func NewRandomX(n int, flags ...Flag) (Hasher, error) {
	collection := &hasherCollection{
		flags: flags,
	}

	if err := collection.initStates(n); err != nil {
		return nil, err
	}
	return collection, nil
}

func newRandomXState(flags ...Flag) (*hasherState, error) {

	applyFlags := randomx.GetFlags()
	for _, f := range flags {
		if f == FlagLargePages {
			applyFlags |= randomx.RANDOMX_FLAG_LARGE_PAGES
		} else if f == FlagFullMemory {
			applyFlags |= randomx.RANDOMX_FLAG_FULL_MEM
		} else if f == FlagSecure {
			applyFlags |= randomx.RANDOMX_FLAG_SECURE
		}
	}
	h := &hasherState{
		flags: applyFlags,
	}
	h.cache = randomx.NewCache(h.flags)

	if dataset := randomx.NewDataset(h.cache); dataset == nil {
		h.cache.Close()
		return nil, errors.New("couldn't initialize dataset")
	} else {
		h.dataset = dataset
	}

	if vm := randomx.NewVM(h.dataset); vm == nil {
		h.cache.Close()
		return nil, errors.New("couldn't initialize dataset")
	} else {
		h.vm = vm
	}

	return h, nil
}

func (h *hasherState) Init(key []byte) (err error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.key = make([]byte, len(key))
	copy(h.key, key)

	utils.Logf("RandomX", "Initializing to seed %s", fasthex.EncodeToString(h.key))
	h.cache.Init(h.key)
	randomx.InitDatasetParallel(h.dataset, runtime.NumCPU())

	utils.Logf("RandomX", "Initialized to seed %s", fasthex.EncodeToString(h.key))

	return nil
}

func (h *hasherState) Hash(input []byte) (output types.Hash) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.vm.CalculateHash(input, (*[32]byte)(&output))
	runtime.KeepAlive(input)
	return
}

func (h *hasherState) Close() {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.vm.Close()
	h.cache.Close()
}
