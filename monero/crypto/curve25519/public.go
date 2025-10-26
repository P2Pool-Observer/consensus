package curve25519

import (
	"database/sql/driver"
	"errors"
	"unsafe"

	fasthex "github.com/tmthrgd/go-hex"
)

const PublicKeySize = 32

var ZeroPublicKeyBytes = PublicKeyBytes{}

type VarTimePublicKey = PublicKey[VarTimeOperations]
type ConstantTimePublicKey = PublicKey[ConstantTimeOperations]

type PublicKey[T PointOperations] struct {
	p Point
}

func To[T2 PointOperations, T1 PointOperations](u *PublicKey[T1]) *PublicKey[T2] {
	return (*PublicKey[T2])(unsafe.Pointer(u))
}

func FromPoint[T PointOperations](u *Point) *PublicKey[T] {
	return (*PublicKey[T])(unsafe.Pointer(u))
}

func (v *PublicKey[T]) NewPoint(u *Point) *PublicKey[T] {
	n := new(PublicKey[T])
	n.p.Set(u)
	return n
}

func (v *PublicKey[T]) op() T {
	var t T
	return t
}

func (v *PublicKey[T]) Add(p, q *PublicKey[T]) *PublicKey[T] {
	v.op().Add(&v.p, &p.p, &q.p)
	return v
}

func (v *PublicKey[T]) Subtract(p, q *PublicKey[T]) *PublicKey[T] {
	v.op().Subtract(&v.p, &p.p, &q.p)
	return v
}

func (v *PublicKey[T]) ScalarBaseMult(x *Scalar) *PublicKey[T] {
	v.op().ScalarBaseMult(&v.p, x)
	return v
}

func (v *PublicKey[T]) ScalarMult(x *Scalar, q *PublicKey[T]) *PublicKey[T] {
	v.op().ScalarMult(&v.p, x, &q.p)
	return v
}

func (v *PublicKey[T]) ScalarMultPrecomputed(x *Scalar, q *Generator) *PublicKey[T] {
	v.op().ScalarMultPrecomputed(&v.p, x, q)
	return v
}

func (v *PublicKey[T]) MultByCofactor(q *PublicKey[T]) *PublicKey[T] {
	v.p.MultByCofactor(&q.p)
	return v
}

func (v *PublicKey[T]) DoubleScalarBaseMult(a *Scalar, A *PublicKey[T], b *Scalar) *PublicKey[T] {
	v.op().DoubleScalarBaseMult(&v.p, a, &A.p, b)
	return v
}

func (v *PublicKey[T]) DoubleScalarBaseMultPrecomputed(a *Scalar, A *Generator, b *Scalar) *PublicKey[T] {
	v.op().DoubleScalarBaseMultPrecomputed(&v.p, a, A, b)
	return v
}

func (v *PublicKey[T]) DoubleScalarMult(a *Scalar, A *PublicKey[T], b *Scalar, B *PublicKey[T]) *PublicKey[T] {
	v.op().DoubleScalarMult(&v.p, a, &A.p, b, &B.p)
	return v
}

func (v *PublicKey[T]) DoubleScalarBasePrecomputed(a *Scalar, A *Generator, b *Scalar, B *Generator) *PublicKey[T] {
	v.op().DoubleScalarMultPrecomputed(&v.p, a, A, b, B)
	return v
}

func (v *PublicKey[T]) IsSmallOrder() bool {
	return v.op().IsSmallOrder(&v.p)
}

func (v *PublicKey[T]) IsTorsionFree() bool {
	return v.op().IsTorsionFree(&v.p)
}

func (v *PublicKey[T]) Bytes() PublicKeyBytes {
	return PublicKeyBytes(v.p.Bytes())
}

func (v *PublicKey[T]) Slice() []byte {
	return v.p.Bytes()
}

func (v *PublicKey[T]) String() string {
	return fasthex.EncodeToString(v.Slice())
}

func (v *PublicKey[T]) P() *Point {
	return &v.p
}

// Montgomery Convert the Ed25519 point to Montgomery
// Equivalent to ConvertPointE
func (v *PublicKey[T]) Montgomery() (out X25519PublicKey) {
	copy(out[:], v.p.BytesMontgomery())
	return out
}

type PublicKeyBytes [PublicKeySize]byte

func (k *PublicKeyBytes) Slice() []byte {
	return (*k)[:]
}

func (k *PublicKeyBytes) Point() *ConstantTimePublicKey {
	return DecodeCompressedPoint(new(ConstantTimePublicKey), *k)
}

func (k *PublicKeyBytes) String() string {
	return fasthex.EncodeToString(k.Slice())
}

func (k *PublicKeyBytes) Scan(src any) error {
	if src == nil {
		return nil
	} else if buf, ok := src.([]byte); ok {
		if len(buf) == 0 {
			return nil
		}
		if len(buf) != PublicKeySize {
			return errors.New("invalid key size")
		}
		copy((*k)[:], buf)

		return nil
	}
	return errors.New("invalid type")
}

func (k *PublicKeyBytes) Value() (driver.Value, error) {
	var zeroPubKey PublicKeyBytes
	if *k == zeroPubKey {
		return nil, nil
	}
	return []byte((*k)[:]), nil
}

func (k *PublicKeyBytes) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || len(b) == 2 {
		return nil
	}

	if len(b) != PublicKeySize*2+2 {
		return errors.New("wrong key size")
	}

	if _, err := fasthex.Decode(k[:], b[1:len(b)-1]); err != nil {
		return err
	} else {
		return nil
	}
}

func (k *PublicKeyBytes) MarshalJSON() ([]byte, error) {
	var buf [PublicKeySize*2 + 2]byte
	buf[0] = '"'
	buf[PublicKeySize*2+1] = '"'
	fasthex.Encode(buf[1:], k[:])
	return buf[:], nil
}
