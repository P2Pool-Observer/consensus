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

const ScratchpadSize = 2 * 1024 * 1024

type State struct {
	scratchpad [ScratchpadSize / 8]uint64 // 2 MiB scratchpad for memhard loop
	finalState [25]uint64                 // state of kecnak1600
	_          [8]byte                    // padded to keep 16-byte align (0x2000d0)

	blocks    [16]uint64            // temporary chunk/pointer of data
	roundKeys [aesRounds * 4]uint32 // 10 rounds, instead of 14 as in standard AES-256

	code       [V4_NUM_INSTRUCTIONS_MAX + 1]V4Instruction
	codeHeight uint64
}

func (cn *State) SumR(data []byte, height uint64, prehashed bool) types.Hash {
	return cn.sum(data, R, height, prehashed)
}

func (cn *State) Sum(data []byte, variant Variant, prehashed bool) types.Hash {
	return cn.sum(data, variant, 0, prehashed)
}

// sum Computes the hash of <data> (which consists of <length> bytes), returning the
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
func (cn *State) sum(data []byte, variant Variant, height uint64, prehashed bool) types.Hash {
	var (
		// used in memory hard
		a, b, c, d [2]uint64

		// for variant 1
		v1Tweak uint64

		// for variant 2+
		e          [2]uint64
		_a         [2]uint64
		divResult  uint64
		sqrtResult uint64

		// for variant 4 / R
		r [9]uint32
	)

	if !prehashed {
		// CNS008 sec.3 Scratchpad Initialization
		hasher := sha3.NewLegacyKeccak256()
		_, _ = utils.WriteNoEscape(hasher, data)
		// trigger pad and permute
		_, _ = utils.ReadNoEscape(hasher.(io.Reader), nil)
		// #nosec G103 -- fixed length read
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&cn.finalState)), len(cn.finalState)*8), keccakStatePtr(hasher)[:])
	} else {
		if len(data) < len(cn.finalState)*8 {
			panic("cryptonight: state length too short")
		}
		// #nosec G103 -- fixed length read
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&cn.finalState)), len(cn.finalState)*8), data)
	}

	if variant == V1 {
		if len(data) < 43 {
			panic("cryptonight: variant 2 requires at least 43 bytes of input")
		}
		v1Tweak = cn.finalState[24] ^ binary.LittleEndian.Uint64(data[35:43])
	}

	if variant == R {
		r[0] = uint32(cn.finalState[12])
		r[1] = uint32(cn.finalState[12] >> 32)
		r[2] = uint32(cn.finalState[13])
		r[3] = uint32(cn.finalState[13] >> 32)
		if cn.codeHeight == 0 || cn.codeHeight != height {
			r_init(&cn.code, height)
			cn.codeHeight = height
		}
	}

	// scratchpad init
	aes_expand_key(cn.finalState[:4], &cn.roundKeys)
	copy(cn.blocks[:], cn.finalState[8:24])

	for i := 0; i < ScratchpadSize/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes_rounds(cn.blocks[j:j+2], &cn.roundKeys)
		}
		copy(cn.scratchpad[i:i+16], cn.blocks[:16])
	}

	// CNS008 sec.4 Memory-Hard Loop
	a[0] = cn.finalState[0] ^ cn.finalState[4]
	a[1] = cn.finalState[1] ^ cn.finalState[5]
	b[0] = cn.finalState[2] ^ cn.finalState[6]
	b[1] = cn.finalState[3] ^ cn.finalState[7]
	if variant >= V2 {
		e[0] = cn.finalState[8] ^ cn.finalState[10]
		e[1] = cn.finalState[9] ^ cn.finalState[11]
		divResult = cn.finalState[12]
		sqrtResult = cn.finalState[13]
	}

	for range 1 << 19 {
		_a[0] = a[0]
		_a[1] = a[1]

		addr := (a[0] & 0x1ffff0) >> 3
		aes_single_round(c[:2], cn.scratchpad[addr:addr+2], &a)

		if variant >= V2 {
			// since we use []uint64 instead of []uint8 as scratchpad, the offset applies too
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			chunk0_0 := cn.scratchpad[offset0+0]
			chunk0_1 := cn.scratchpad[offset0+1]
			chunk1_0 := cn.scratchpad[offset1+0]
			chunk1_1 := cn.scratchpad[offset1+1]
			chunk2_0 := cn.scratchpad[offset2+0]
			chunk2_1 := cn.scratchpad[offset2+1]

			cn.scratchpad[offset0+0] = chunk2_0 + e[0]
			cn.scratchpad[offset0+1] = chunk2_1 + e[1]
			cn.scratchpad[offset2+0] = chunk1_0 + _a[0]
			cn.scratchpad[offset2+1] = chunk1_1 + _a[1]
			cn.scratchpad[offset1+0] = chunk0_0 + b[0]
			cn.scratchpad[offset1+1] = chunk0_1 + b[1]

			if variant == R {
				c[0] = (c[0] ^ chunk2_0) ^ (chunk0_0 ^ chunk1_0)
				c[1] = (c[1] ^ chunk2_1) ^ (chunk0_1 ^ chunk1_1)
			}
		}

		cn.scratchpad[addr+0] = b[0] ^ c[0]
		cn.scratchpad[addr+1] = b[1] ^ c[1]

		if variant == V1 {
			t := cn.scratchpad[addr+1] >> 24
			t = ((^t)&1)<<4 | (((^t)&1)<<4&t)<<1 | (t&32)>>1
			cn.scratchpad[addr+1] ^= t << 24
		}

		addr = (c[0] & 0x1ffff0) >> 3
		d[0] = cn.scratchpad[addr]
		d[1] = cn.scratchpad[addr+1]

		if variant == V2 || variant == V3 {
			// equivalent to VARIANT2_PORTABLE_INTEGER_MATH in slow-hash.c
			// VARIANT2_INTEGER_MATH_DIVISION_STEP
			d[0] ^= divResult ^ (sqrtResult << 32)
			divisor := (c[0]+(sqrtResult<<1))&0xffffffff | 0x80000001
			divResult = (c[1]/divisor)&0xffffffff | (c[1]%divisor)<<32
			sqrtInput := c[0] + divResult

			// VARIANT2_INTEGER_MATH_SQRT_STEP_FP64 and
			// VARIANT2_INTEGER_MATH_SQRT_FIXUP
			sqrtResult = sqrt(sqrtInput)
		}

		if variant == R {
			d[0] ^= uint64(r[0]+r[1]) | (uint64(r[2]+r[3]) << 32)

			r[4], r[5] = uint32(a[0]), uint32(a[1])
			r[6] = uint32(b[0])
			r[7], r[8] = uint32(e[0]), uint32(e[1])
			r_interpreter(&cn.code, &r)

			a[0] ^= uint64(r[2]) | ((uint64)(r[3]) << 32)
			a[1] ^= uint64(r[0]) | ((uint64)(r[1]) << 32)
		}

		// byteMul
		hi, lo := bits.Mul64(c[0], d[0])

		if variant >= V2 {
			// shuffle again, it's the same process as above
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			chunk0_0 := cn.scratchpad[offset0+0]
			chunk0_1 := cn.scratchpad[offset0+1]
			chunk1_0 := cn.scratchpad[offset1+0]
			chunk1_1 := cn.scratchpad[offset1+1]
			chunk2_0 := cn.scratchpad[offset2+0]
			chunk2_1 := cn.scratchpad[offset2+1]

			// VARIANT2_2
			if variant == V2 || variant == V3 {

				chunk0_0 ^= hi
				chunk0_1 ^= lo
				hi ^= chunk1_0
				lo ^= chunk1_1
			}

			cn.scratchpad[offset0+0] = chunk2_0 + e[0]
			cn.scratchpad[offset0+1] = chunk2_1 + e[1]
			cn.scratchpad[offset2+0] = chunk1_0 + _a[0]
			cn.scratchpad[offset2+1] = chunk1_1 + _a[1]
			cn.scratchpad[offset1+0] = chunk0_0 + b[0]
			cn.scratchpad[offset1+1] = chunk0_1 + b[1]

			// re-assign higher-order of b
			e[0] = b[0]
			e[1] = b[1]

			if variant == R {
				c[0] = (c[0] ^ chunk2_0) ^ (chunk0_0 ^ chunk1_0)
				c[1] = (c[1] ^ chunk2_1) ^ (chunk0_1 ^ chunk1_1)
			}
		}

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

		b[0] = c[0]
		b[1] = c[1]
	}

	// CNS008 sec.5 Result Calculation
	aes_expand_key(cn.finalState[4:8], &cn.roundKeys)
	tmp := cn.finalState[8:24] // a temp pointer

	for i := 0; i < ScratchpadSize/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cn.scratchpad[i+j+0] ^= tmp[j+0]
			cn.scratchpad[i+j+1] ^= tmp[j+1]
			aes_rounds(cn.scratchpad[i+j:i+j+2], &cn.roundKeys)
		}
		tmp = cn.scratchpad[i : i+16]
	}

	copy(cn.finalState[8:24], tmp)
	keccakF1600(&cn.finalState)

	var sum types.Hash

	// #nosec G103 -- checked exact len
	stateBuf := unsafe.Slice((*byte)(unsafe.Pointer(&cn.finalState)), len(cn.finalState)*8)
	finalHash(uint8(cn.finalState[0]), stateBuf, sum[:])

	return sum
}
