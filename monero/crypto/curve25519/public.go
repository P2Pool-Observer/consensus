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

// PublicKey An Edwards25519 point with canonical encoding
type PublicKey[T PointOperations] struct {
	p  Point
	op T
}

func To[T2 PointOperations, T1 PointOperations](u *PublicKey[T1]) *PublicKey[T2] {
	return (*PublicKey[T2])(unsafe.Pointer(u))
}

func FromPoint[T PointOperations](u *Point) *PublicKey[T] {
	return (*PublicKey[T])(unsafe.Pointer(u))
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *PublicKey[T]) Equal(u *PublicKey[T]) int {
	return v.P().Equal(u.P())
}

func (v *PublicKey[T]) Add(p, q *PublicKey[T]) *PublicKey[T] {
	add(v.op, &v.p, &p.p, &q.p)
	return v
}

func (v *PublicKey[T]) Subtract(p, q *PublicKey[T]) *PublicKey[T] {
	subtract(v.op, &v.p, &p.p, &q.p)
	return v
}

func (v *PublicKey[T]) Double(x *PublicKey[T]) *PublicKey[T] {
	double(v.op, &v.p, &x.p)
	return v
}

func (v *PublicKey[T]) Negate(x *PublicKey[T]) *PublicKey[T] {
	negate(v.op, &v.p, &x.p)
	return v
}

func (v *PublicKey[T]) ScalarBaseMult(x *Scalar) *PublicKey[T] {
	scalarBaseMult(v.op, &v.p, x)
	return v
}

func (v *PublicKey[T]) ScalarMult(x *Scalar, q *PublicKey[T]) *PublicKey[T] {
	scalarMult(v.op, &v.p, x, &q.p)
	return v
}

func (v *PublicKey[T]) ScalarMultPrecomputed(x *Scalar, q *Generator) *PublicKey[T] {
	scalarMultPrecomputed(v.op, &v.p, x, q)
	return v
}

func (v *PublicKey[T]) MultByCofactor(q *PublicKey[T]) *PublicKey[T] {
	multByCofactor(v.op, &v.p, &q.p)
	return v
}

func (v *PublicKey[T]) DoubleScalarBaseMult(a *Scalar, A *PublicKey[T], b *Scalar) *PublicKey[T] {
	doubleScalarBaseMult(v.op, &v.p, a, &A.p, b)
	return v
}

func (v *PublicKey[T]) DoubleScalarBaseMultPrecomputed(a *Scalar, A *Generator, b *Scalar) *PublicKey[T] {
	doubleScalarBaseMultPrecomputed(v.op, &v.p, a, A, b)
	return v
}

func (v *PublicKey[T]) DoubleScalarMult(a *Scalar, A *PublicKey[T], b *Scalar, B *PublicKey[T]) *PublicKey[T] {
	doubleScalarMult(v.op, &v.p, a, &A.p, b, &B.p)
	return v
}

func (v *PublicKey[T]) DoubleScalarMultPrecomputed(a *Scalar, A *Generator, b *Scalar, B *Generator) *PublicKey[T] {
	doubleScalarMultPrecomputed(v.op, &v.p, a, A, b, B)
	return v
}

func (v *PublicKey[T]) DoubleScalarMultPrecomputedB(a *Scalar, A *PublicKey[T], b *Scalar, B *Generator) *PublicKey[T] {
	doubleScalarMultPrecomputedB(v.op, &v.p, a, &A.p, b, B)
	return v
}

func (v *PublicKey[T]) IsSmallOrder() bool {
	return isSmallOrder(v.op, &v.p)
}

func (v *PublicKey[T]) IsTorsionFree() bool {
	return isTorsionFree(v.op, &v.p)
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
func (v *PublicKey[T]) Montgomery() (out MontgomeryPoint) {
	copy(out[:], v.p.BytesMontgomery())
	return out
}

// PublicKeyBytes A compressed Edwards25519 Y point
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
