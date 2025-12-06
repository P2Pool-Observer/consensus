// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package threefish

import (
	"crypto/cipher"
	"errors"
)

const (
	// TweakSize The size of the tweak in bytes.
	TweakSize = 16
	// C240 is the key schedule constant
	C240 = 0x1bd11bdaa9fc1a22
	// BlockSize512 The block size of Threefish-512 in bytes.
	BlockSize512 = 64
)

var errKeySize = errors.New("invalid key size")

// NewCipher returns a cipher.Block implementing the Threefish cipher.
// The length of the key must be 32, 64 or 128 byte.
// The length of the tweak must be TweakSize.
// The returned cipher implements:
//   - Threefish-256  - if len(key) = 32
//   - Threefish-512  - if len(key) = 64
//   - Threefish-1024 - if len(key) = 128
func NewCipher(tweak *[TweakSize]byte, key []byte) (cipher.Block, error) {
	switch k := len(key); k {
	default:
		return nil, errKeySize
	case BlockSize512:
		return newCipher512(tweak, key), nil
	}
}

// IncrementTweak Increment the tweak by the ctr argument.
// Skein can consume messages up to 2^96 -1 bytes.
func IncrementTweak(tweak *[3]uint64, ctr uint64) {
	t0 := tweak[0]
	tweak[0] += ctr
	if tweak[0] < t0 {
		t1 := tweak[1]
		tweak[1] = (t1 + 1) & 0x00000000FFFFFFFF
	}
}

// The threefish-512 tweakable blockcipher
type threefish512 struct {
	keys  [9]uint64
	tweak [3]uint64
}

func (t *threefish512) BlockSize() int { return BlockSize512 }

func bytesToBlock512(block *[8]uint64, src []byte) {
	for i := range block {
		j := i * 8
		block[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 | uint64(src[j+3])<<24 |
			uint64(src[j+4])<<32 | uint64(src[j+5])<<40 | uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}
}

func block512ToBytes(dst []byte, block *[8]uint64) {
	for i, v := range block {
		j := i * 8
		dst[j] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}
