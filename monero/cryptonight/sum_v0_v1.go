package cryptonight

import (
	"encoding/binary"
	"io"
	"math/bits"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"golang.org/x/crypto/sha3" //nolint:depguard
)

func (cn *State) sum_v0_v1(data []byte, variant Variant, prehashed bool) types.Hash {
	var (
		// used in memory hard
		a, b, c, d [2]uint64

		addr uint32

		// for variant 1
		v1Tweak uint64
	)

	if !prehashed {
		// CNS008 sec.3 Scratchpad Initialization
		hasher := sha3.NewLegacyKeccak256()
		_, _ = utils.WriteNoEscape(hasher, data)
		// trigger pad and permute
		_, _ = utils.ReadNoEscape(hasher.(io.Reader), nil)
		// #nosec G103 -- fixed length read
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&cn.keccakState)), len(cn.keccakState)*8), keccakStatePtr(hasher)[:])
	} else {
		if len(data) < len(cn.keccakState)*8 {
			panic("cryptonight: state length too short")
		}
		// #nosec G103 -- fixed length read
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&cn.keccakState)), len(cn.keccakState)*8), data)
	}

	if variant == V1 {
		if len(data) < 43 {
			panic("cryptonight: variant 2 requires at least 43 bytes of input")
		}
		v1Tweak = cn.keccakState[24] ^ binary.LittleEndian.Uint64(data[35:43])
	}

	// scratchpad init
	aes_expand_key(cn.keccakState[:4], &cn.roundKeys)
	copy(cn.blocks[:], cn.keccakState[8:24])
	for i := 0; i < ScratchpadSize/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes_rounds((*[2]uint64)(cn.blocks[j:]), &cn.roundKeys)
		}
		copy(cn.scratchpad[i:i+16], cn.blocks[:16])
	}

	// CNS008 sec.4 Memory-Hard Loop
	a[0] = cn.keccakState[0] ^ cn.keccakState[4]
	a[1] = cn.keccakState[1] ^ cn.keccakState[5]
	b[0] = cn.keccakState[2] ^ cn.keccakState[6]
	b[1] = cn.keccakState[3] ^ cn.keccakState[7]

	for range 1 << 19 {
		addr = uint32((a[0] & 0x1ffff0) >> 3)
		aes_single_round(&c, (*[2]uint64)(cn.scratchpad[addr:]), &a)

		cn.scratchpad[addr+0] = b[0] ^ c[0]
		cn.scratchpad[addr+1] = b[1] ^ c[1]

		if variant == V1 {
			t := cn.scratchpad[addr+1] >> 24
			t = ((^t)&1)<<4 | (((^t)&1)<<4&t)<<1 | (t&32)>>1
			cn.scratchpad[addr+1] ^= t << 24
		}

		addr = uint32((c[0] & 0x1ffff0) >> 3)
		d[0] = cn.scratchpad[addr]
		d[1] = cn.scratchpad[addr+1]

		// byteMul
		hi, lo := bits.Mul64(c[0], d[0])

		// byteAdd
		a[0] += hi
		a[1] += lo

		cn.scratchpad[addr+0] = a[0]
		cn.scratchpad[addr+1] = a[1]

		if variant == V1 {
			cn.scratchpad[addr+1] ^= v1Tweak
		}

		a[0] ^= d[0]
		a[1] ^= d[1]

		b = c
	}

	// CNS008 sec.5 Result Calculation
	aes_expand_key(cn.keccakState[4:8], &cn.roundKeys)
	tmp := ([16]uint64)(cn.keccakState[8:]) // a temp pointer

	for i := 0; i < ScratchpadSize/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cn.scratchpad[i+j+0] ^= tmp[j+0]
			cn.scratchpad[i+j+1] ^= tmp[j+1]
			aes_rounds((*[2]uint64)(cn.scratchpad[i+j:]), &cn.roundKeys)
		}
		tmp = ([16]uint64)(cn.scratchpad[i:])
	}

	copy(cn.keccakState[8:24], tmp[:])
	keccakF1600(&cn.keccakState)

	var sum types.Hash

	// #nosec G103 -- checked exact len
	stateBuf := unsafe.Slice((*byte)(unsafe.Pointer(&cn.keccakState)), len(cn.keccakState)*8)
	finalHash(uint8(cn.keccakState[0]), stateBuf, sum[:])

	return sum
}
