package crypto

import (
	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/edwards25519/field"
)

type X25519PublicKey [32]byte

var ZeroX25519PublicKey X25519PublicKey

var X25519Basepoint = X25519PublicKey{9}

func X25519ScalarBaseMult(dst *X25519PublicKey, s *edwards25519.Scalar) {
	// X25519ScalarMult(dst, scalar, X25519Basepoint)

	var p edwards25519.Point
	p.UnsafeVarTimeScalarBaseMult(s)

	*dst = ConvertPointE(&p)
}

func X25519ScalarMult[T1 ~[32]byte](dst *X25519PublicKey, scalar T1, point X25519PublicKey) {
	var x1, x2, z2, x3, z3, tmp0, tmp1 field.Element
	// TODO maybe just SetBytes
	x1.SetBytesPropagate(point[:])
	x2.One()
	x3.Set(&x1)
	z3.One()

	swap := 0
	for pos := 254; pos >= 0; pos-- {
		b := scalar[pos/8] >> uint(pos&7)
		b &= 1
		swap ^= int(b)
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = int(b)

		tmp0.Subtract(&x3, &z3)
		tmp1.Subtract(&x2, &z2)
		x2.Add(&x2, &z2)
		z2.Add(&x3, &z3)
		z3.Multiply(&tmp0, &x2)
		z2.Multiply(&z2, &tmp1)
		tmp0.Square(&tmp1)
		tmp1.Square(&x2)
		x3.Add(&z3, &z2)
		z2.Subtract(&z3, &z2)
		x2.Multiply(&tmp1, &tmp0)
		tmp1.Subtract(&tmp1, &tmp0)
		z2.Square(&z2)

		z3.Mult32(&tmp1, 121666)
		x3.Square(&x3)
		tmp0.Add(&tmp0, &z3)
		z3.Multiply(&x1, &z2)
		z2.Multiply(&tmp1, &tmp0)
	}

	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)

	z2.Invert(&z2)
	x2.Multiply(&x2, &z2)

	copy(dst[:], x2.Bytes())
}

func ConvertPointE(v *edwards25519.Point) (out X25519PublicKey) {
	copy(out[:], v.BytesMontgomery())
	return out
}
