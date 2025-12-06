package cryptonight

import (
	"math/bits"
	"unsafe"
)

var te0, te1, te2, te3 = encLut[0], encLut[1], encLut[2], encLut[3]

//go:nosplit
func soft_aesenc(state *[4]uint32, key *[4]uint32) {

	s0 := state[0]
	s1 := state[1]
	s2 := state[2]
	s3 := state[3]

	state[0] = key[0] ^ te0[uint8(s0)] ^ te1[uint8(s1>>8)] ^ te2[uint8(s2>>16)] ^ te3[uint8(s3>>24)]
	state[1] = key[1] ^ te0[uint8(s1)] ^ te1[uint8(s2>>8)] ^ te2[uint8(s3>>16)] ^ te3[uint8(s0>>24)]
	state[2] = key[2] ^ te0[uint8(s2)] ^ te1[uint8(s3>>8)] ^ te2[uint8(s0>>16)] ^ te3[uint8(s1>>24)]
	state[3] = key[3] ^ te0[uint8(s3)] ^ te1[uint8(s0>>8)] ^ te2[uint8(s1>>16)] ^ te3[uint8(s2>>24)]
}

// Powers of x mod poly in GF(2).
var powx = [16]byte{
	0x01,
	0x02,
	0x04,
	0x08,
	0x10,
	0x20,
	0x40,
	0x80,
	0x1b,
	0x36,
	0x6c,
	0xd8,
	0xab,
	0x4d,
	0x9a,
	0x2f,
}

// Apply sbox0 to each byte in w.
func subw(w uint32) uint32 {
	return uint32(sbox0[w>>24])<<24 |
		uint32(sbox0[w>>16&0xff])<<16 |
		uint32(sbox0[w>>8&0xff])<<8 |
		uint32(sbox0[w&0xff])
}

// Rotate
func rotw(w uint32) uint32 { return w<<8 | w>>24 }

const aesRounds = 10

func aes_expand_key(key []uint64, roundKeys *[aesRounds * 4]uint32) {
	for i := range 4 {
		roundKeys[2*i] = bits.ReverseBytes32(uint32(key[i]))
		roundKeys[2*i+1] = bits.ReverseBytes32(uint32(key[i] >> 32))
	}

	for i := 8; i < 40; i++ {
		t := roundKeys[i-1]
		if i%8 == 0 {
			t = subw(rotw(t)) ^ (uint32(powx[i/8-1]) << 24)
		} else if 8 > 6 && i%8 == 4 {
			t = subw(t)
		}
		roundKeys[i] = roundKeys[i-8] ^ t
	}
	// TODO: make this all little endian
	for i := range roundKeys {
		roundKeys[i] = bits.ReverseBytes32(roundKeys[i])
	}
}

func aes_rounds(state []uint64, roundKeys *[aesRounds * 4]uint32) {
	// #nosec G103
	state32 := (*[4]uint32)(unsafe.Pointer(unsafe.SliceData(state)))
	// #nosec G103
	rkey32 := (*[aesRounds][4]uint32)(unsafe.Pointer(roundKeys))

	for r := range aesRounds {
		soft_aesenc(state32, &rkey32[r])
	}
}

func aes_single_round(dst, src []uint64, roundKey *[2]uint64) {
	copy(dst, src)
	// #nosec G103
	dst32 := (*[4]uint32)(unsafe.Pointer(unsafe.SliceData(dst)))
	// #nosec G103
	rkey32 := (*[4]uint32)(unsafe.Pointer(roundKey))
	soft_aesenc(dst32, rkey32)
}
