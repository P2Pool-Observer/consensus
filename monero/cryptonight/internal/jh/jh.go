// Package jh implements JH-256 algorithm.
package jh

import (
	"encoding/binary"
	"hash"
	"unsafe"
)

// For memset
var zeroBuf64Byte [64]byte

type State struct {
	HashBitLen       int          // the message digest size
	databitlen       uint64       // the message size in bits
	datasizeInBuffer uint64       // the size of the message remained in buffer; assumed to be multiple of 8bits except for the last partial block at the end of the message
	X                [8][2]uint64 // the 1024-bit State, ( X[i][0] || X[i][1] ) is the ith row of the State in the pseudocod
	buffer           [64]byte     // the 512-bit message block to be hashed
}

func Sum256(b []byte) []byte {
	h := New256()
	h.Write(b)

	return h.Sum(nil)
}

func New256() hash.Hash {
	return &State{HashBitLen: 256, X: JH256H0}
}

func (s *State) Reset() {
	s.HashBitLen = 256
	s.databitlen = 0
	s.datasizeInBuffer = 0
	s.X = JH256H0
}

func (s *State) Size() int      { return 32 }
func (s *State) BlockSize() int { return 64 }

// Write hash each 512-bit message block, except the last partial block
func (s *State) Write(data []byte) (n int, err error) {
	index := uint64(0) // the starting address of the data to be compressed
	databitlen := uint64(len(data)) * 8
	s.databitlen += databitlen

	// if there is remaining data in the buffer, fill it to a full message block first
	// we assume that the size of the data in the buffer is the multiple of 8 bits if it is not at the end of a message

	// There is data in the buffer, but the incoming data is insufficient for a full block
	if s.datasizeInBuffer > 0 && s.datasizeInBuffer+databitlen < 512 {
		if databitlen&7 == 0 {
			copy(s.buffer[s.datasizeInBuffer>>3:], data[:64-(s.datasizeInBuffer>>3)])
		} else {
			copy(s.buffer[s.datasizeInBuffer>>3:], data[:64-(s.datasizeInBuffer>>3)+1])
		}
		s.datasizeInBuffer += databitlen
		databitlen = 0
	}

	// There is data in the buffer, and the incoming data is sufficient for a full block
	if s.datasizeInBuffer > 0 && s.datasizeInBuffer+databitlen >= 512 {
		copy(s.buffer[s.datasizeInBuffer>>3:], data[:64-(s.datasizeInBuffer>>3)])
		index = 64 - (s.datasizeInBuffer >> 3)
		databitlen -= 512 - s.datasizeInBuffer
		s.f8()
		s.datasizeInBuffer = 0
	}

	// hash the remaining full message blocks
	for databitlen >= 512 {
		copy(s.buffer[:], data[index:index+64])
		s.f8()
		index += 64
		databitlen -= 512
	}

	// store the partial block into buffer, assume that -- if part of the last byte is not part of the message, then that part consists of bits*/
	if databitlen > 0 {
		if databitlen&7 == 0 {
			copy(s.buffer[:((databitlen&0x1ff)>>3)], data[index:])
		} else {
			copy(s.buffer[:((databitlen&0x1ff)>>3)+1], data[index:])
		}
		s.datasizeInBuffer = databitlen
	}

	return len(data), nil
}

// Sum pads the message, process the padded block(s), truncate the hash value H to obtain the message digest
func (s *State) Sum(b []byte) []byte {
	var i uint64

	if s.databitlen&0x1ff == 0 {
		// pad the message when databitlen is multiple of 512 bits, then process the padded block
		s.buffer = zeroBuf64Byte
		s.buffer[0] = 0x80
		s.buffer[63] = uint8(s.databitlen)
		s.buffer[62] = uint8(s.databitlen >> 8)
		s.buffer[61] = uint8(s.databitlen >> 16)
		s.buffer[60] = uint8(s.databitlen >> 24)
		s.buffer[59] = uint8(s.databitlen >> 32)
		s.buffer[58] = uint8(s.databitlen >> 40)
		s.buffer[57] = uint8(s.databitlen >> 48)
		s.buffer[56] = uint8(s.databitlen >> 56)
		s.f8()
	} else {
		// set the rest of the bytes in the buffer to 0
		if s.datasizeInBuffer&7 == 0 {
			for i = (s.databitlen & 0x1ff) >> 3; i < 64; i++ {
				s.buffer[i] = 0
			}
		} else {
			for i = ((s.databitlen & 0x1ff) >> 3) + 1; i < 64; i++ {
				s.buffer[i] = 0
			}
		}

		// pad and process the partial block when databitlen is not multiple of 512 bits, then hash the padded blocks
		s.buffer[(s.databitlen&0x1ff)>>3] |= 1 << (7 - (s.databitlen & 7))

		s.f8()
		s.buffer = zeroBuf64Byte
		s.buffer[63] = uint8(s.databitlen)
		s.buffer[62] = uint8(s.databitlen >> 8)
		s.buffer[61] = uint8(s.databitlen >> 16)
		s.buffer[60] = uint8(s.databitlen >> 24)
		s.buffer[59] = uint8(s.databitlen >> 32)
		s.buffer[58] = uint8(s.databitlen >> 40)
		s.buffer[57] = uint8(s.databitlen >> 48)
		s.buffer[56] = uint8(s.databitlen >> 56)
		s.f8()
	}

	// #nosec 103
	return append(b, (*[32]byte)(unsafe.Pointer(&s.X[6][0]))[:]...)
}

// The compression function F8.
func (s *State) f8() {
	// xor the 512-bit message with the fist half of the 1024-bit hash State
	for i := range 8 {
		s.X[i>>1][i&1] ^= binary.LittleEndian.Uint64(s.buffer[8*i:])
	}

	// the bijective function E8
	s.e8()

	// xor the 512-bit message with the second half of the 1024-bit hash State
	for i := range 8 {
		s.X[(8+i)>>1][(8+i)&1] ^= binary.LittleEndian.Uint64(s.buffer[8*i:])
	}
}

func (s *State) round(roundNumber, offset, i int) {
	SS(&s.X[0][i], &s.X[2][i], &s.X[4][i], &s.X[6][i], &s.X[1][i], &s.X[3][i], &s.X[5][i], &s.X[7][i], e8BitsliceRoundconstant[roundNumber+offset][i], e8BitsliceRoundconstant[roundNumber+offset][i+2])
	L(&s.X[0][i], &s.X[2][i], &s.X[4][i], &s.X[6][i], &s.X[1][i], &s.X[3][i], &s.X[5][i], &s.X[7][i])
}

// The bijective function E8, in bitslice form.
func (s *State) e8() {
	var temp0 uint64

	for round := 0; round < 42; round += 7 {
		for i := range 2 {
			s.round(round, 0, i)
			for j := range 4 {
				SWAP1(&s.X[j*2+1][i])
			}
		}
		for i := range 2 {
			s.round(round, 1, i)
			for j := range 4 {
				SWAP2(&s.X[j*2+1][i])
			}
		}
		for i := range 2 {
			s.round(round, 2, i)
			for j := range 4 {
				SWAP4(&s.X[j*2+1][i])
			}
		}
		for i := range 2 {
			s.round(round, 3, i)
			for j := range 4 {
				SWAP8(&s.X[j*2+1][i])
			}
		}
		for i := range 2 {
			s.round(round, 4, i)
			for j := range 4 {
				SWAP16(&s.X[j*2+1][i])
			}
		}
		for i := range 2 {
			s.round(round, 5, i)
			for j := range 4 {
				SWAP32(&s.X[j*2+1][i])
			}
		}
		for i := range 2 {
			s.round(round, 6, i)
		}

		// round 7*round+6: swapping layer
		for i := 1; i < 8; i += 2 {
			temp0 = s.X[i][0]
			s.X[i][0] = s.X[i][1]
			s.X[i][1] = temp0
		}
	}
}
