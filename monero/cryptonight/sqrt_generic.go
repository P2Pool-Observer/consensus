//go:build !amd64 || purego

package cryptonight

import "math"

//go:nosplit
func v2_sqrt(in uint64) uint64 {
	out := uint64(
		math.Sqrt(
			float64(in)+1<<64,
		)*2 - 1<<33,
	)

	s := out >> 1
	b := out & 1
	r2 := s*(s+b) + (out << 32)
	if r2+b > in {
		out--
	}

	if r2+(1<<32) < in-s {
		out++
	}

	return out
}
