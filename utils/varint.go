package utils

import (
	"encoding/binary"
	"errors"
	"io"
)

var errOverflow = errors.New("binary: varint overflows a 64-bit integer")

var ErrNonCanonicalEncoding = errors.New("binary: varint has non canonical encoding")

// ReadCanonicalUvarint reads an encoded unsigned integer from r and returns it as a uint64.
// The error is ErrNonCanonicalEncoding if non-canonical bytes were read.
// The error is [io.EOF] only if no bytes were read.
// If an [io.EOF] happens after reading some but not all the bytes,
// ReadCanonicalUvarint returns [io.ErrUnexpectedEOF].
func ReadCanonicalUvarint(r io.ByteReader) (uint64, error) {
	var x uint64
	var s uint
	for i := 0; i < binary.MaxVarintLen64; i++ {
		b, err := r.ReadByte()
		if err != nil {
			if i > 0 && err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return x, err
		}
		if i > 0 && b == 0 {
			return x, ErrNonCanonicalEncoding
		}
		if b < 0x80 {
			if i == binary.MaxVarintLen64-1 && b > 1 {
				return x, errOverflow
			}
			return x | uint64(b)<<s, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return x, errOverflow
}

// CanonicalUvarint decodes a uint64 from buf and returns that value and the
// number of bytes read (> 0). If an error occurred, the value is 0
// and the number of bytes n is <= 0 meaning:
//   - n == 0: buf too small;
//   - n < 0: value larger than 64 bits (overflow) and -n is the number of
//     bytes read.
//
// The function errors if non-canonical bytes were read.
func CanonicalUvarint(buf []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range buf {
		if i == binary.MaxVarintLen64 {
			// Catch byte reads past MaxVarintLen64.
			// See issue https://golang.org/issues/41185
			return 0, -(i + 1) // overflow
		}
		if i > 0 && b == 0 {
			return 0, -(i + 1) // overflow mask TODO: use different mask
		}
		if b < 0x80 {
			if i == binary.MaxVarintLen64-1 && b > 1 {
				return 0, -(i + 1) // overflow
			}
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

const (
	VarIntLen1 = uint64(1 << ((iota + 1) * 7))
	VarIntLen2
	VarIntLen3
	VarIntLen4
	VarIntLen5
	VarIntLen6
	VarIntLen7
	VarIntLen8
	VarIntLen9
)

/*

	Checked using this

	var uVarInt64Thresholds [binary.MaxVarintLen64 + 1]uint64

	lastSize := 0
	for i := uint64(1); i > 0 && i < math.MaxUint64; i <<= 1 {
		s := UVarInt64Size(i)
		if s != lastSize {

			n := uVarInt64Thresholds[lastSize]
			ix := sort.Search(int(i-n), func(i int) bool {
				return UVarInt64Size(n+uint64(i)) > lastSize
			})
			uVarInt64Thresholds[s] = n + uint64(ix)
			lastSize = s
		}
	}

	log.Print(uVarInt64Thresholds)

*/

func UVarInt64SliceSize[T uint64 | int](v []T) (n int) {
	for i := range v {
		n += UVarInt64Size(v[i])
	}
	return
}

func UVarInt64Size[T uint64 | int | uint8](v T) (n int) {
	x := uint64(v)

	if x < VarIntLen1 {
		return 1
	} else if x < VarIntLen2 {
		return 2
	} else if x < VarIntLen3 {
		return 3
	} else if x < VarIntLen4 {
		return 4
	} else if x < VarIntLen5 {
		return 5
	} else if x < VarIntLen6 {
		return 6
	} else if x < VarIntLen7 {
		return 7
	} else if x < VarIntLen8 {
		return 8
	} else if x < VarIntLen9 {
		return 9
	} else {
		return binary.MaxVarintLen64
	}
}
