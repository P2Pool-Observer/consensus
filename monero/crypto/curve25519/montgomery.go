package curve25519

import (
	"crypto/subtle"
	"database/sql/driver"
	"errors"

	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/edwards25519/field"
	fasthex "github.com/tmthrgd/go-hex"
)

// MontgomeryPoint A Curve25519 u coordinate (Montgomery)
type MontgomeryPoint [PublicKeySize]byte

func (v *MontgomeryPoint) Slice() []byte {
	return (*v)[:]
}

func (v *MontgomeryPoint) String() string {
	return fasthex.EncodeToString(v.Slice())
}

func (v *MontgomeryPoint) ScalarBaseMult(x *Scalar) {
	MontgomeryScalarBaseMult[ConstantTimeOperations](v, x)
}

func (v *MontgomeryPoint) ScalarMult(x *Scalar, q *MontgomeryPoint) {
	MontgomeryUnclampedScalarMult(v, PrivateKeyBytes(x.Bytes()), *q)
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *MontgomeryPoint) Equal(u *MontgomeryPoint) int {
	return subtle.ConstantTimeCompare(v[:], u[:])
}

// Edwards Attempt conversion of v to an Edwards25519 point
// Note that not every MontgomeryPoint has a valid point
func (v *MontgomeryPoint) Edwards(sign int) (*ConstantTimePublicKey, error) {
	var u field.Element
	_, _ = u.SetBytes(v.Slice())

	return DecodeMontgomeryPoint(new(ConstantTimePublicKey), &u, sign)
}

func (v *MontgomeryPoint) Scan(src any) error {
	if src == nil {
		return nil
	} else if buf, ok := src.([]byte); ok {
		if len(buf) == 0 {
			return nil
		}
		if len(buf) != PublicKeySize {
			return errors.New("invalid key size")
		}
		copy((*v)[:], buf)

		return nil
	}
	return errors.New("invalid type")
}

func (v *MontgomeryPoint) Value() (driver.Value, error) {
	if *v == ZeroMontgomeryPoint {
		return nil, nil
	}
	return []byte((*v)[:]), nil
}

func (v *MontgomeryPoint) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || len(b) == 2 {
		return nil
	}

	if len(b) != PublicKeySize*2+2 {
		return errors.New("wrong key size")
	}

	if _, err := fasthex.Decode(v[:], b[1:len(b)-1]); err != nil {
		return err
	} else {
		return nil
	}
}

func (v *MontgomeryPoint) MarshalJSON() ([]byte, error) {
	var buf [PublicKeySize*2 + 2]byte
	buf[0] = '"'
	buf[PublicKeySize*2+1] = '"'
	fasthex.Encode(buf[1:], v[:])
	return buf[:], nil
}

var ZeroMontgomeryPoint MontgomeryPoint

var MontgomeryBasepoint = MontgomeryPoint{9}

// DecodeMontgomeryPoint Decode a Montgomery coordinate and sign to Ed25519
// Constant time
//
// To decompress the Montgomery u coordinate to an `EdwardsPoint`,
// we apply the birational map to obtain the Edwards y coordinate, then do Edwards decompression.
func DecodeMontgomeryPoint[T PointOperations](r *PublicKey[T], u *field.Element, sign int) (*PublicKey[T], error) {
	if u == nil || u.Equal(_NEGATIVE_ONE) == 1 {
		return nil, errors.New("invalid coordinate")
	}

	var tmp1, tmp2 field.Element

	// The birational map is y = (u-1)/(u+1).
	y := u.Multiply(
		tmp1.Subtract(u, _ONE),
		tmp2.Invert(tmp2.Add(u, _ONE)),
	)

	var yBytes [PublicKeySize]byte
	copy(yBytes[:], y.Bytes())
	yBytes[31] ^= byte(sign << 7)
	if _, err := r.SetBytes(yBytes[:]); err != nil {
		return nil, err
	}
	return r, nil
}

// MontgomeryScalarBaseMult Multiply a Scalar by the Basepoint, and place result in dst
// This is done by doing it in Edwards25519 then converting to Montgomery
func MontgomeryScalarBaseMult[T PointOperations](dst *MontgomeryPoint, s *Scalar) {
	// MontgomeryUnclampedScalarMult(dst, scalar, MontgomeryBasepoint)

	var p PublicKey[T]
	p.ScalarBaseMult(s)

	*dst = p.Montgomery()
}

// MontgomeryUnclampedScalarMult Multiply a Scalar by the given point, and place result in dst
// Note this is done unclamped, compared to common implementations
// Precondition: scalar must be mod l, otherwise top bit is effectively clamped: scalar[31] &= 127
//
// Constant Time Montgomery Ladder
func MontgomeryUnclampedScalarMult[T1 ~[32]byte](dst *MontgomeryPoint, scalar T1, point MontgomeryPoint) {
	var x1, x2, z2, x3, z3, tmp0, tmp1 field.Element
	_, _ = x1.SetBytes(point[:])

	x2.One()
	x3.Set(&x1)
	z3.One()

	swap := 0
	// Topmost bit is always unset due to scalar mod l precondition
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

		z3.Mult121666(&tmp1)
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

func ConvertPointE(v *edwards25519.Point) (out MontgomeryPoint) {
	copy(out[:], v.BytesMontgomery())
	return out
}

// MontgomerySmallOrderPoints
// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L17
var MontgomerySmallOrderPoints = [7]MontgomeryPoint{
	/* 0 (order 4) */
	{0},
	/* 1 (order 1) */
	{1},
	/* 325606250916557431795983626356110631294008115727848805560023387167927233504
	   (order 8) */
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	/* 39382357235489614581723060781553021112529911719440698176882885853963445705823
	   (order 8) */
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	/* p-1 (order 2) */
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	/* p (=0, order 4) */
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	/* p+1 (=1, order 1) */
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}
