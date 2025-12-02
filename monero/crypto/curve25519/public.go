package curve25519

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519" //nolint:depguard
	fasthex "github.com/tmthrgd/go-hex"
)

type Point = edwards25519.Point

const PublicKeySize = 32

var ZeroPublicKeyBytes = PublicKeyBytes{}

type VarTimePublicKey = PublicKey[VarTimeOperations]
type ConstantTimePublicKey = PublicKey[ConstantTimeOperations]

// PublicKey An Edwards25519 point with canonical encoding
type PublicKey[T PointOperations] struct {
	p Point
}

func assertSize[T PointOperations]() {
	// assert the size of PublicKey[T] is same as Point
	var pub PublicKey[T]
	var point Point
	if unsafe.Sizeof(pub) != unsafe.Sizeof(point) {
		panic(fmt.Sprintf("sizeof(pub)[%d] != sizeof(point)[%d]", unsafe.Sizeof(pub), unsafe.Sizeof(point)))
	}
}

func To[T2 PointOperations, T1 PointOperations](u *PublicKey[T1]) *PublicKey[T2] {
	return (*PublicKey[T2])(u)
}

func FromPoint[T PointOperations](u *Point) *PublicKey[T] {
	// #nosec G103 -- safe, we check size on assert
	return (*PublicKey[T])(unsafe.Pointer(u))
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *PublicKey[T]) Equal(u *PublicKey[T]) int {
	return v.P().Equal(u.P())
}

func (v *PublicKey[T]) op() T {
	var ret T
	return ret
}

func (v *PublicKey[T]) Add(p, q *PublicKey[T]) *PublicKey[T] {
	add(v.op(), &v.p, &p.p, &q.p)
	return v
}

func (v *PublicKey[T]) Subtract(p, q *PublicKey[T]) *PublicKey[T] {
	subtract(v.op(), &v.p, &p.p, &q.p)
	return v
}

func (v *PublicKey[T]) Double(x *PublicKey[T]) *PublicKey[T] {
	double(v.op(), &v.p, &x.p)
	return v
}

func (v *PublicKey[T]) Negate(x *PublicKey[T]) *PublicKey[T] {
	negate(v.op(), &v.p, &x.p)
	return v
}

func (v *PublicKey[T]) ScalarBaseMult(x *Scalar) *PublicKey[T] {
	scalarBaseMult(v.op(), &v.p, x)
	return v
}

func (v *PublicKey[T]) ScalarMult(x *Scalar, q *PublicKey[T]) *PublicKey[T] {
	scalarMult(v.op(), &v.p, x, &q.p)
	return v
}

func (v *PublicKey[T]) ScalarMultPrecomputed(x *Scalar, q *Generator) *PublicKey[T] {
	scalarMultPrecomputed(v.op(), &v.p, x, q)
	return v
}

func (v *PublicKey[T]) MultByCofactor(q *PublicKey[T]) *PublicKey[T] {
	multByCofactor(v.op(), &v.p, &q.p)
	return v
}

func (v *PublicKey[T]) DoubleScalarBaseMult(a *Scalar, A *PublicKey[T], b *Scalar) *PublicKey[T] {
	doubleScalarBaseMult(v.op(), &v.p, a, &A.p, b)
	return v
}

func (v *PublicKey[T]) DoubleScalarBaseMultPrecomputed(a *Scalar, A *Generator, b *Scalar) *PublicKey[T] {
	doubleScalarBaseMultPrecomputed(v.op(), &v.p, a, A, b)
	return v
}

func (v *PublicKey[T]) DoubleScalarMult(a *Scalar, A *PublicKey[T], b *Scalar, B *PublicKey[T]) *PublicKey[T] {
	doubleScalarMult(v.op(), &v.p, a, &A.p, b, &B.p)
	return v
}

func (v *PublicKey[T]) DoubleScalarMultPrecomputed(a *Scalar, A *Generator, b *Scalar, B *Generator) *PublicKey[T] {
	doubleScalarMultPrecomputed(v.op(), &v.p, a, A, b, B)
	return v
}

func (v *PublicKey[T]) DoubleScalarMultPrecomputedB(a *Scalar, A *PublicKey[T], b *Scalar, B *Generator) *PublicKey[T] {
	doubleScalarMultPrecomputedB(v.op(), &v.p, a, &A.p, b, B)
	return v
}

func (v *PublicKey[T]) MultiScalarMult(scalars []*Scalar, points []*PublicKey[T]) *PublicKey[T] {
	// #nosec G103 -- converts to internal Point representation
	return v.MultiScalarMultPoints(scalars, unsafe.Slice((**Point)(unsafe.Pointer(unsafe.SliceData(points))), len(points)))
}

func (v *PublicKey[T]) MultiScalarMultPoints(scalars []*Scalar, points []*Point) *PublicKey[T] {
	v.op().MultiScalarMult(&v.p, scalars, points)
	return v
}

var identity = edwards25519.NewIdentityPoint()

func (v *PublicKey[T]) Set(x *PublicKey[T]) *PublicKey[T] {
	v.P().Set(x.P())
	return v
}

func (v *PublicKey[T]) Identity() *PublicKey[T] {
	v.P().Set(identity)
	return v
}

func (v *PublicKey[T]) IsIdentity() int {
	return v.P().Equal(identity)
}

func (v *PublicKey[T]) IsSmallOrder() bool {
	return isSmallOrder(v.op(), &v.p)
}

func (v *PublicKey[T]) IsTorsionFree() bool {
	return isTorsionFree(v.op(), &v.p)
}

// SetBytes Decompress a canonically-encoded Ed25519 point.
// Canonical encoded means that the Y coordinate is reduced, and that negative zero is not allowed
// Equivalent to Monero's check_key or ge_frombytes_vartime (with constant or vartime implementations)
//
// Ed25519 is of order `8 * basepointOrder`. This function ensures each of those `8 * basepointOrder` points have a
// singular encoding by checking points aren't encoded with an unreduced field element,
// and aren't negative when the negative is equivalent (0 == -0).
//
// Since this decodes an Ed25519 point, it does not check the point is in the prime-order
// subgroup. Torsioned points do have a canonical encoding, and only aren't canonical when
// considered in relation to the prime-order subgroup.
//
// To verify torsion use PublicKey.IsTorsionFree
func (v *PublicKey[T]) SetBytes(x []byte) (*PublicKey[T], error) {
	_, err := setBytes(v.op(), &v.p, x)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (v *PublicKey[T]) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	return append(preAllocatedBuf, v.p.Bytes()...), nil
}

func (v *PublicKey[T]) FromReader(reader utils.ReaderAndByteReader) (err error) {
	var pub PublicKeyBytes

	if _, err = utils.ReadFullNoEscape(reader, pub[:]); err != nil {
		return err
	}
	if _, err = v.SetBytes(pub[:]); err != nil {
		return err
	}
	return nil
}

// Bytes Compresses an Ed25519 to its canonical compressed Y
func (v *PublicKey[T]) Bytes() []byte {
	return v.p.Bytes()
}

// AsBytes Equivalent to Bytes but with PublicKeyBytes return type
func (v *PublicKey[T]) AsBytes() PublicKeyBytes {
	return PublicKeyBytes(v.p.Bytes())
}

func (v *PublicKey[T]) String() string {
	return fasthex.EncodeToString(v.Bytes())
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
	p, _ := new(ConstantTimePublicKey).SetBytes(k[:])
	return p
}

func (k *PublicKeyBytes) PointVarTime() *VarTimePublicKey {
	p, _ := new(VarTimePublicKey).SetBytes(k[:])
	return p
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
		return nil, nil //nolint:nilnil
	}
	return (*k)[:], nil
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

func (k PublicKeyBytes) MarshalJSON() ([]byte, error) {
	var buf [PublicKeySize*2 + 2]byte
	buf[0] = '"'
	buf[PublicKeySize*2+1] = '"'
	fasthex.Encode(buf[1:], k[:])
	return buf[:], nil
}

func assertPoint[P any, S any, T curve.ExtraCurvePoint[P, S]](p *P, s *S) T {
	return T(p)
}

var _ = assertPoint(new(VarTimePublicKey), new(Scalar))
var _ = assertPoint(new(ConstantTimePublicKey), new(Scalar))
