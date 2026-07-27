package curve25519

import (
	"encoding/binary"
	"errors"

	fasthex "git.gammaspectra.live/P2Pool/go-hex"
)

// UnreducedScalar An unreduced scalar.
//
// While most of modern Monero enforces scalars be reduced, certain legacy parts of the code did
// not. These section can generally simply be read as a scalar/reduced into a scalar when the time
// comes, yet a couple have non-standard reductions performed.
//
// This struct delays scalar conversions and offers the non-standard reduction.
//
// See https://github.com/monero-project/monero/issues/8438 or https://www.moneroinflation.com/static/data_py/report_scalars_df.pdf
type UnreducedScalar PrivateKeyBytes

// naf5 Computes the non-adjacent form of this scalar with width 5.
//
// This matches Monero's `slide` function and intentionally gives incorrect outputs under
// certain conditions in order to match Monero.
//
// This function does not execute in constant time and must only be used with public data.
// Variable time
func (s *UnreducedScalar) naf5() (naf [256]int8) {
	const bits = PrivateKeySize * 8
	for pos := range bits {
		b := s[pos/8] >> uint(pos&7)

		// #nosec G602
		naf[pos] = int8(b & 1)
	}

	for i := range naf {
		if naf[i] != 0 {
			// if the bit is a one, work our way up through the window
			// combining the bits with this bit.
			for b := 1; b < 6; b++ {
				if (i + b) >= bits {
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
						for k := i + b; k < bits; k++ {
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
	naf5 := s.naf5()
	for i := len(naf5) - 1; i >= 0; i-- {
		n := naf5[i]
		out.Add(out, out)
		if n > 0 {
			out.Add(out, precomputedScalars[n/2])
		} else if n < 0 {
			out.Subtract(out, precomputedScalars[(-n)/2])
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
	for i := range precomputedScalars {
		var buf PrivateKeyBytes
		binary.LittleEndian.PutUint64(buf[:], uint64(i*2+1))
		precomputedScalars[i] = buf.Scalar()
	}
}
