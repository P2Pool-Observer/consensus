package cryptonight

import (
	"io"
	"math/bits"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"golang.org/x/crypto/sha3" //nolint:depguard
)

func (cn *State) sum_v2_r(data []byte, variant Variant, height uint64, prehashed bool) types.Hash {
	var (
		// used in memory hard
		a, b, c, d [2]uint64

		addr uint32

		// for variant 2+
		e          [2]uint64
		_a         [2]uint64
		divResult  uint64
		sqrtResult uint64

		// for variant 4 / R
		r0, r1, r2, r3 uint32
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

	if variant == R {
		r0 = uint32(cn.keccakState[12])
		r1 = uint32(cn.keccakState[12] >> 32)
		r2 = uint32(cn.keccakState[13])
		r3 = uint32(cn.keccakState[13] >> 32)
		if cn.codeHeight == 0 || cn.codeHeight != height {
			r_init(&cn.ops, height, [5]*uint32{&cn.r4, &cn.r5, &cn.r6, &cn.r7, &cn.r8})
			cn.codeHeight = height
		}
	}

	// scratchpad init
	aes_expand_key(cn.keccakState[:4], &cn.roundKeys)
	copy(cn.blocks[:], cn.keccakState[8:24])

	for i := 0; i < ScratchpadSize/8; i += 16 {
		aes_rounds(&cn.blocks, &cn.roundKeys)
		copy(cn.scratchpad[i:i+16], cn.blocks[:16])
	}

	// CNS008 sec.4 Memory-Hard Loop
	a[0] = cn.keccakState[0] ^ cn.keccakState[4]
	a[1] = cn.keccakState[1] ^ cn.keccakState[5]
	b[0] = cn.keccakState[2] ^ cn.keccakState[6]
	b[1] = cn.keccakState[3] ^ cn.keccakState[7]
	e[0] = cn.keccakState[8] ^ cn.keccakState[10]
	e[1] = cn.keccakState[9] ^ cn.keccakState[11]

	if variant == V2 || variant == V3 {
		divResult = cn.keccakState[12]
		sqrtResult = cn.keccakState[13]
	}

	for range 1 << 19 {
		addr = uint32((a[0] & 0x1ffff0) >> 3)
		aes_single_round(&c, (*[2]uint64)(cn.scratchpad[addr:]), &a)

		_a = a

		// since we use []uint64 instead of []uint8 as scratchpad, the offset applies too
		offset0 := addr ^ 0x02
		offset1 := addr ^ 0x04
		offset2 := addr ^ 0x06

		chunk0_0 := cn.scratchpad[offset0]
		chunk0_1 := cn.scratchpad[offset0+1]
		chunk1_0 := cn.scratchpad[offset1]
		chunk1_1 := cn.scratchpad[offset1+1]
		chunk2_0 := cn.scratchpad[offset2]
		chunk2_1 := cn.scratchpad[offset2+1]

		cn.scratchpad[offset0] = chunk2_0 + e[0]
		cn.scratchpad[offset0+1] = chunk2_1 + e[1]
		cn.scratchpad[offset2] = chunk1_0 + _a[0]
		cn.scratchpad[offset2+1] = chunk1_1 + _a[1]
		cn.scratchpad[offset1] = chunk0_0 + b[0]
		cn.scratchpad[offset1+1] = chunk0_1 + b[1]

		if variant == R {
			c[0] ^= chunk2_0 ^ chunk0_0 ^ chunk1_0
			c[1] ^= chunk2_1 ^ chunk0_1 ^ chunk1_1
		}

		cn.scratchpad[addr] = b[0] ^ c[0]
		cn.scratchpad[addr+1] = b[1] ^ c[1]

		addr = uint32((c[0] & 0x1ffff0) >> 3)
		d[0] = cn.scratchpad[addr]
		d[1] = cn.scratchpad[addr+1]

		if variant == V2 || variant == V3 {
			// equivalent to VARIANT2_PORTABLE_INTEGER_MATH in slow-hash.c
			// VARIANT2_INTEGER_MATH_DIVISION_STEP
			d[0] ^= divResult ^ (sqrtResult << 32)
			divisor := (c[0]+(sqrtResult<<1))&0xffffffff | 0x80000001
			divResult = (c[1]/divisor)&0xffffffff | (c[1]%divisor)<<32

			// VARIANT2_INTEGER_MATH_SQRT_STEP_FP64 and
			// VARIANT2_INTEGER_MATH_SQRT_FIXUP
			sqrtResult = v2_sqrt(c[0] + divResult)
		} else if variant == R {
			d[0] ^= uint64(r0+r1) | (uint64(r2+r3) << 32)

			cn.r4, cn.r5 = uint32(a[0]), uint32(a[1])
			cn.r6 = uint32(b[0])
			cn.r7, cn.r8 = uint32(e[0]), uint32(e[1])
			r0, r1, r2, r3 = r_op_interpreter(&cn.ops, r0, r1, r2, r3)

			a[0] ^= uint64(r2) | (uint64(r3) << 32)
			a[1] ^= uint64(r0) | (uint64(r1) << 32)
		}

		// byteMul
		hi, lo := bits.Mul64(c[0], d[0])

		// shuffle again, it's the same process as above
		offset0 = addr ^ 0x02
		offset1 = addr ^ 0x04
		offset2 = addr ^ 0x06

		chunk0_0 = cn.scratchpad[offset0]
		chunk0_1 = cn.scratchpad[offset0+1]
		chunk1_0 = cn.scratchpad[offset1]
		chunk1_1 = cn.scratchpad[offset1+1]
		chunk2_0 = cn.scratchpad[offset2]
		chunk2_1 = cn.scratchpad[offset2+1]

		// VARIANT2_2
		if variant == V2 || variant == V3 {
			chunk0_0 ^= hi
			chunk0_1 ^= lo
			hi ^= chunk1_0
			lo ^= chunk1_1
		}

		cn.scratchpad[offset0] = chunk2_0 + e[0]
		cn.scratchpad[offset0+1] = chunk2_1 + e[1]
		cn.scratchpad[offset2] = chunk1_0 + _a[0]
		cn.scratchpad[offset2+1] = chunk1_1 + _a[1]
		cn.scratchpad[offset1] = chunk0_0 + b[0]
		cn.scratchpad[offset1+1] = chunk0_1 + b[1]

		if variant == R {
			c[0] ^= chunk2_0 ^ chunk0_0 ^ chunk1_0
			c[1] ^= chunk2_1 ^ chunk0_1 ^ chunk1_1
		}

		// byteAdd
		a[0] += hi
		a[1] += lo

		cn.scratchpad[addr] = a[0]
		cn.scratchpad[addr+1] = a[1]

		// re-assign higher-order of b
		e = b

		a[0] ^= d[0]
		a[1] ^= d[1]

		b = c
	}

	// CNS008 sec.5 Result Calculation
	aes_expand_key(cn.keccakState[4:8], &cn.roundKeys)
	tmp := ([16]uint64)(cn.keccakState[8:]) // a temp pointer

	for i := 0; i < ScratchpadSize/8; i += 16 {
		for j := range tmp {
			cn.scratchpad[i+j] ^= tmp[j]
		}
		aes_rounds((*[16]uint64)(cn.scratchpad[i:]), &cn.roundKeys)
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
