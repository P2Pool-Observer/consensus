package curve

import (
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
	Invert(x *F) *F

	// Setters

	Set(x *F) *F
	Select(a, b *F, cond int) *F
	Zero() *F
	One() *F

	// Comparison
	Equal(x *F) int
}

// Field A full implementation of a Field element with helper utilities
type Field[F any] interface {
	BasicField[F]

	// Operations
	Square(x *F) *F
	Absolute(x *F) *F
	Sqrt(x *F) *F

	// Marshaling

	SetBytes(x []byte) (*F, error)
	SetWideBytes(x []byte) (*F, error)
	Bytes() []byte

	// Comparison
	IsZero() int
	IsNegative() int
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
