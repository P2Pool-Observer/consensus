package utils

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"strconv"
)

func PreviousPowerOfTwo(x uint64) int {
	if x == 0 {
		return 0
	}
	return 1 << (64 - bits.LeadingZeros64(x) - 1)
}

const (
	VarIntLen1 uint64 = 1 << ((iota + 1) * 7)
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

func UVarInt64Size[T uint64 | int](v T) (n int) {
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

// ParseUint64 parses uint64 from s.
//
// It is equivalent to strconv.ParseUint(s, 10, 64), but is faster.
//
// From https://github.com/valyala/fastjson
func ParseUint64(s []byte) (uint64, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("cannot parse uint64 from empty string")
	}
	i := uint(0)
	d := uint64(0)
	j := i
	for i < uint(len(s)) {
		if s[i] >= '0' && s[i] <= '9' {
			d = d*10 + uint64(s[i]-'0')
			i++
			if i > 18 {
				// The integer part may be out of range for uint64.
				// Fall back to slow parsing.
				dd, err := strconv.ParseUint(string(s), 10, 64)
				if err != nil {
					return 0, err
				}
				return dd, nil
			}
			continue
		}
		break
	}
	if i <= j {
		return 0, fmt.Errorf("cannot parse uint64 from %q", s)
	}
	if i < uint(len(s)) {
		// Unparsed tail left.
		return 0, fmt.Errorf("unparsed tail left after parsing uint64 from %q: %q", s, s[i:])
	}
	return d, nil
}
