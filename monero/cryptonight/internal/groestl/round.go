package groestl

import (
	"encoding/binary"
	"errors"
)

// Performs compression function. Returns nil on success, error otherwise.
func (d *Digest) transform(data []byte) error {
	if (len(data) % blockSize) != 0 {
		return errors.New("data len in transform is not a multiple of BlockSize")
	}

	cols := 0

	eb := d.blocks + uint64(len(data)/blockSize)

	var m, hxm [columns]uint64
	for d.blocks < eb {

		for i := range columns {
			m[i] = binary.BigEndian.Uint64(data[cols*8 : (cols+1)*8])
			cols++
			hxm[i] = d.chaining[i] ^ m[i]
		}

		round(&hxm, 'p')
		round(&m, 'q')

		for i := range columns {
			d.chaining[i] ^= hxm[i] ^ m[i]
		}

		d.blocks++
	}

	return nil
}

// Performs last compression. After this function, data
// is ready for truncation.
func (d *Digest) finalTransform() {
	var h [columns]uint64

	for i := range columns {
		h[i] = d.chaining[i]
	}

	round(&h, 'p')

	for i := range columns {
		d.chaining[i] ^= h[i]
	}

	d.blocks++
}

// Performs whole set of rounds on data provided in x. Variant denotes type
// of permutation being performed. P and Q are for groestl-512
// and lowercase are for groestl-256
func round(x *[columns]uint64, variant rune) {
	for i := range rounds {
		addRoundConstant(x, i, variant)
		subBytes(x)
		shiftBytes(x, variant)
		mixBytes(x)
	}
}

// AddRoundConstant transformation for data provided in x. Variant denotes type
// of permutation being performed. P and Q are for groestl-512
// and lowercase are for groestl-256
func addRoundConstant(x *[columns]uint64, r int, variant rune) {
	switch variant {
	case 'p':
		for i, l := 0, len(x); i < l; i++ {
			// byte from row 0: ((col >> (8*7)) & 0xFF)
			// we want to xor the byte below with row 0
			// therefore we have to shift it by 8*7 bits
			x[i] ^= uint64((i<<4)^r) << (8 * 7)
		}
	case 'q':
		for i, l := 0, len(x); i < l; i++ {
			x[i] ^= ^uint64(0) ^ uint64((i<<4)^r)
		}
	default:
		panic("invalid variant")
	}
}

// SubBytes transformation for data provided in x.
func subBytes(x *[columns]uint64) {
	var newCol [8]byte
	for i, l := 0, len(x); i < l; i++ {
		for j := range 8 {
			newCol[j] = sbox[pickRow(x[i], j)]
		}
		x[i] = binary.BigEndian.Uint64(newCol[:])
	}
}

var shiftVectorp = [8]int{0, 1, 2, 3, 4, 5, 6, 7}
var shiftVectorq = [8]int{1, 3, 5, 7, 0, 2, 4, 6}

// ShiftBytes transformation for data provided in x. Variant denotes type
// of permutation being performed. P and Q are for groestl-512
// and lowercase are for groestl-256
func shiftBytes(x *[columns]uint64, variant rune) {
	var shiftVector *[8]int
	switch variant {
	case 'p':
		shiftVector = &shiftVectorp
	case 'q':
		shiftVector = &shiftVectorq
	default:
		panic("invalid variant")
	}
	old := *x
	for i := range columns {
		x[i] = uint64(pickRow(old[(i+shiftVector[0])%columns], 0))
		for j := 1; j < 8; j++ {
			x[i] <<= 8
			x[i] ^= uint64(pickRow(old[(i+shiftVector[j])%columns], j))
		}
	}
}

// MixBytes transformation for data provided in x.
func mixBytes(x *[columns]uint64) {
	// this part is tricky
	// so here comes yet another rough translation straight from reference implementation

	mul2 := func(b uint8) uint8 { return (b << 1) ^ (0x1B * ((b >> 7) & 1)) }
	mul3 := func(b uint8) uint8 { return (mul2(b) ^ (b)) }
	mul4 := func(b uint8) uint8 { return mul2(mul2(b)) }
	mul5 := func(b uint8) uint8 { return (mul4(b) ^ (b)) }
	mul7 := func(b uint8) uint8 { return (mul4(b) ^ mul2(b) ^ (b)) }

	var temp [8]uint8
	for i, l := 0, len(x); i < l; i++ {
		for j := range 8 {
			temp[j] =
				mul2(pickRow(x[i], (j+0)%8)) ^
					mul2(pickRow(x[i], (j+1)%8)) ^
					mul3(pickRow(x[i], (j+2)%8)) ^
					mul4(pickRow(x[i], (j+3)%8)) ^
					mul5(pickRow(x[i], (j+4)%8)) ^
					mul3(pickRow(x[i], (j+5)%8)) ^
					mul5(pickRow(x[i], (j+6)%8)) ^
					mul7(pickRow(x[i], (j+7)%8))
		}
		x[i] = binary.BigEndian.Uint64(temp[:])
	}
}

func pickRow(col uint64, i int) byte {
	return byte((col >> (8 * (7 - i))) & 0xFF)
}
