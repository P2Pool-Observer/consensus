package curve25519

import (
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/edwards25519" //nolint:depguard
	fasthex "github.com/tmthrgd/go-hex"
)

type Scalar = edwards25519.Scalar

// basepointOrder is the order of the Ristretto group and of the Ed25519 basepoint, i.e., l = 2^252 + 27742317777372353535851937790883648493.
var basepointOrder = [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}

// limit = basepointOrder * 15, basepointOrder fits 15 times in 32 bytes (iow, 15 basepointOrder is the highest multiple of basepointOrder that fits in 32 bytes)
var limit = [32]byte{0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0}

//go:nosplit
func ScalarIsLimit32[T ~[PrivateKeySize]byte](a T) bool {
	for n := 31; n >= 0; n-- {
		if a[n] < limit[n] {
			return true
		} else if a[n] > limit[n] {
			return false
		}
	}

	return false
}
func ScalarIsReduced32[T ~[PrivateKeySize]byte](a T) bool {
	for n := 31; n >= 0; n-- {
		if a[n] < basepointOrder[n] {
			return true
		} else if a[n] > basepointOrder[n] {
			return false
		}
	}

	return false
}

//go:nosplit
func load3(in []byte) (result int64) {
	_ = in[2] // bounds check hint to compiler; see golang.org/issue/14808
	result = int64(in[0]) | (int64(in[1]) << 8) | (int64(in[2]) << 16)
	return
}

//go:nosplit
func load4(in []byte) (result int64) {
	return int64(binary.LittleEndian.Uint32(in))
}

// ScalarReduce32
// also called sc_reduce32
// 256-bit s integer modulo basepointOrder
//
//go:nosplit
func ScalarReduce32[T ~[PrivateKeySize]byte](s *T) {
	s0 := 0x1FFFFF & load3((*s)[:])
	s1 := 0x1FFFFF & (load4((*s)[2:]) >> 5)
	s2 := 0x1FFFFF & (load3((*s)[5:]) >> 2)
	s3 := 0x1FFFFF & (load4((*s)[7:]) >> 7)
	s4 := 0x1FFFFF & (load4((*s)[10:]) >> 4)
	s5 := 0x1FFFFF & (load3((*s)[13:]) >> 1)
	s6 := 0x1FFFFF & (load4((*s)[15:]) >> 6)
	s7 := 0x1FFFFF & (load3((*s)[18:]) >> 3)
	s8 := 0x1FFFFF & load3((*s)[21:])
	s9 := 0x1FFFFF & (load4((*s)[23:]) >> 5)
	s10 := 0x1FFFFF & (load3((*s)[26:]) >> 2)
	s11 := load4((*s)[28:]) >> 7
	s12 := int64(0)
	var carry [12]int64
	carry[0] = (s0 + (1 << 20)) >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[2] = (s2 + (1 << 20)) >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[4] = (s4 + (1 << 20)) >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[1] = (s1 + (1 << 20)) >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[3] = (s3 + (1 << 20)) >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[5] = (s5 + (1 << 20)) >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	carry[11] = s11 >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901

	// same as above
	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	(*s)[0] = byte(s0 >> 0)
	(*s)[1] = byte(s0 >> 8)
	(*s)[2] = byte((s0 >> 16) | (s1 << 5))
	(*s)[3] = byte(s1 >> 3)
	(*s)[4] = byte(s1 >> 11)
	(*s)[5] = byte((s1 >> 19) | (s2 << 2))
	(*s)[6] = byte(s2 >> 6)
	(*s)[7] = byte((s2 >> 14) | (s3 << 7))
	(*s)[8] = byte(s3 >> 1)
	(*s)[9] = byte(s3 >> 9)
	(*s)[10] = byte((s3 >> 17) | (s4 << 4))
	(*s)[11] = byte(s4 >> 4)
	(*s)[12] = byte(s4 >> 12)
	(*s)[13] = byte((s4 >> 20) | (s5 << 1))
	(*s)[14] = byte(s5 >> 7)
	(*s)[15] = byte((s5 >> 15) | (s6 << 6))
	(*s)[16] = byte(s6 >> 2)
	(*s)[17] = byte(s6 >> 10)
	(*s)[18] = byte((s6 >> 18) | (s7 << 3))
	(*s)[19] = byte(s7 >> 5)
	(*s)[20] = byte(s7 >> 13)
	(*s)[21] = byte(s8 >> 0)
	(*s)[22] = byte(s8 >> 8)
	(*s)[23] = byte((s8 >> 16) | (s9 << 5))
	(*s)[24] = byte(s9 >> 3)
	(*s)[25] = byte(s9 >> 11)
	(*s)[26] = byte((s9 >> 19) | (s10 << 2))
	(*s)[27] = byte(s10 >> 6)
	(*s)[28] = byte((s10 >> 14) | (s11 << 7))
	(*s)[29] = byte(s11 >> 1)
	(*s)[30] = byte(s11 >> 9)
	(*s)[31] = byte(s11 >> 17)
}

//go:nosplit
func BytesToScalar64(c *Scalar, buf [64]byte) {
	_, _ = c.SetUniformBytes(buf[:])
}

//go:nosplit
func BytesToScalar32(c *Scalar, buf [32]byte) {
	ScalarReduce32(&buf)
	_, _ = c.SetCanonicalBytes(buf[:])
}

var zeroScalar = ZeroPrivateKeyBytes.Scalar()

// UnreducedScalar An unreduced scalar.
//
// While most of modern Monero enforces scalars be reduced, certain legacy parts of the code did
// not. These section can generally simply be read as a scalar/reduced into a scalar when the time
// comes, yet a couple have non-standard reductions performed.
//
// This struct delays scalar conversions and offers the non-standard reduction.
type UnreducedScalar PrivateKeyBytes

// NAF5 Computes the non-adjacent form of this scalar with width 5.
//
// This matches Monero's `slide` function and intentionally gives incorrect outputs under
// certain conditions in order to match Monero.
//
// This function does not execute in constant time and must only be used with public data.
// Variable time
func (s *UnreducedScalar) NAF5() (naf [256]int8) {
	for pos := 0; pos < PrivateKeySize*8; pos++ {
		b := s[pos/8] >> uint(pos&7)

		naf[b] = int8(b)
	}

	for i := range naf {
		if naf[i] != 0 {
			// if the bit is a one, work our way up through the window
			// combining the bits with this bit.
			for b := 1; b < 6; b++ {
				if (i + b) > 256 {
					// if we are at the length of the array then break out
					// the loop.
					break
				}
				// the value of the bit at i+b compared to the bit at i
				if potentialCarry := naf[i+b] << b; potentialCarry != 0 {
					if (naf[i] + potentialCarry) <= 15 {
						// if our current "bit" plus the potential carry is less than 16
						// add it to our current "bit" and set the potential carry bit to 0.
						naf[i] += potentialCarry
						naf[i+b] = 0
					} else if (naf[i] - potentialCarry) >= -15 {
						// else if our current "bit" minus the potential carry is more than -16
						// take it away from our current "bit".
						// we then work our way up through the bits setting ones to zero, when
						// we hit the first zero we change it to one then stop, this is to factor
						// in the minus.
						naf[i] -= potentialCarry
						for k := i + b; k < 256; k++ {
							if naf[k] == 0 {
								naf[k] = 1
								break
							}
							naf[k] = 0
						}
					} else {
						break
					}
				}
			}
		}
	}

	return naf
}

func (s *UnreducedScalar) ScalarVarTime(out *Scalar) *Scalar {
	if s[31]&128 == 0 {
		// Computing the w-NAF of a number can only give an output with 1 more bit than
		// the number, so even if the number isn't reduced, the `slide` function will be
		// correct when the last bit isn't set.
		BytesToScalar32(out, *s)
		return out
	}

	out.Set(zeroScalar)
	for _, n := range s.NAF5() {
		out.Add(out, out)
		if n > 0 {
			out.Add(out, precomputedScalars[n])
		} else if n < 0 {
			out.Subtract(out, precomputedScalars[-n])
		}
	}
	return out
}

func (s *UnreducedScalar) Slice() []byte {
	return (*s)[:]
}

func (s *UnreducedScalar) String() string {
	return fasthex.EncodeToString(s.Slice())
}

func (s *UnreducedScalar) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || len(b) == 2 {
		return nil
	}

	if len(b) != PrivateKeySize*2+2 {
		return errors.New("wrong key size")
	}

	if _, err := fasthex.Decode(s[:], b[1:len(b)-1]); err != nil {
		return err
	} else {
		return nil
	}
}

func (s UnreducedScalar) MarshalJSON() ([]byte, error) {
	var buf [PrivateKeySize*2 + 2]byte
	buf[0] = '"'
	buf[PrivateKeySize*2+1] = '"'
	fasthex.Encode(buf[1:], s[:])
	return buf[:], nil
}

var precomputedScalars [8]*Scalar

//nolint:gochecknoinits
func init() {
	precomputedScalars[0] = (&PrivateKeyBytes{1}).Scalar()
	for i := range precomputedScalars[1:] {
		var buf PrivateKeyBytes
		binary.LittleEndian.PutUint64(buf[:], uint64(i*2+1))
		precomputedScalars[i+1] = buf.Scalar()
	}
}
