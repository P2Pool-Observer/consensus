package curve

import (
	"crypto/subtle"
	"encoding/binary"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// TODO: use Go 1.26 recursive types

type BasicField[F any] interface {
	*F

	// Operations

	Add(a, b *F) *F
	Subtract(a, b *F) *F
	Multiply(a, b *F) *F
	Negate(x *F) *F
	// Invert TODO: fail if Zero??
	// Something like Invert(x *F) (*F, bool)
	Invert(x *F) *F

	// Setters

	Set(x *F) *F
	Select(a, b *F, cond int) *F
	Zero() *F
	One() *F

	// Comparison
	Equal(x *F) int
}

type Field[F any] interface {
	BasicField[F]

	// Operations
	Square(x *F) *F
	Absolute(x *F) *F

	// Marshaling

	SetBytes(x []byte) (*F, error)
	SetWideBytes(x []byte) (*F, error)
	Bytes() []byte

	// Comparison
	IsZero() int
	IsNegative() int

	// Special
	NumBits() int
	Capacity() int
}

type ExtraField[F any] interface {
	Field[F]

	// Operations
	Sqrt(x *F) *F
}

func RandomField[F any, FE Field[F]](k *F, r io.Reader) *F {

	var buf [64]byte
	var zeroElement F
	FE(&zeroElement).Zero()

	for {
		if _, err := utils.ReadNoEscape(r, buf[:]); err != nil {
			panic(err)
		}

		if _, err := FE(k).SetWideBytes(buf[:]); err != nil {
			panic(err)
		}

		if FE(k).Equal(&zeroElement) == 0 {
			return k
		}
	}
}

func FieldFromUint64[F any, FE Field[F]](k *F, v uint64) *F {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	_, err := FE(k).SetBytes(buf[:])
	if err != nil {
		panic(err)
	}
	return k
}

func FieldSliceEqualsVarTime[F any, FE BasicField[F], S ~[]F](a, b S) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if FE(&a[i]).Equal(&b[i]) == 0 {
			return false
		}
	}
	return true
}

// FieldPow sets v = x^y, where y is a little endian order integer exponent, and returns out
// Constant Time. Very Slow.
func FieldPow[F any, FE Field[F]](out *F, x *F, y []byte) *F {
	// compute power table
	var table [16]F
	FE(&table[0]).One()
	FE(&table[1]).Set(x)
	for i := 2; i < 16; i += 2 {
		FE(&table[i]).Square(&table[i/2])
		FE(&table[i+1]).Multiply(&table[i], x)
	}

	FE(out).One()

	var factor F
	for i := len(y) - 1; i >= 0; i-- {
		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		{
			bits := (y[i] >> 4) & 15
			factor = table[0]
			for j := range table[1:] {
				FE(&factor).Select(&table[j+1], &factor, subtle.ConstantTimeEq(int32(bits), int32(j+1)))
			}
			FE(out).Multiply(out, &factor)
		}

		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		{
			bits := y[i] & 15
			factor = table[0]
			for j := range table[1:] {
				FE(&factor).Select(&table[j+1], &factor, subtle.ConstantTimeEq(int32(bits), int32(j+1)))
			}
			FE(out).Multiply(out, &factor)
		}
	}

	return out
}

// FieldPowVarTime sets v = x^y, where y is a little endian order integer exponent, and returns out
// Variable Time. Slow.
func FieldPowVarTime[F any, FE Field[F]](out *F, x *F, y []byte) *F {
	// compute power table
	var table [16]F
	FE(&table[0]).One()
	FE(&table[1]).Set(x)
	for i := 2; i < 16; i += 2 {
		FE(&table[i]).Square(&table[i/2])
		FE(&table[i+1]).Multiply(&table[i], x)
	}

	FE(out).One()

	for i := len(y) - 1; i >= 0; i-- {
		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		{
			bits := (y[i] >> 4) & 15
			FE(out).Multiply(out, &table[bits])
		}

		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		FE(out).Square(out)
		{
			bits := y[i] & 15
			FE(out).Multiply(out, &table[bits])
		}
	}

	return out
}
