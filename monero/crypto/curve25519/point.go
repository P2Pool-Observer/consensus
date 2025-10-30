package curve25519

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/edwards25519/field"
)

type Point = edwards25519.Point

// DecodeMontgomeryPoint
// Constant time
//
// To decompress the Montgomery u coordinate to an `EdwardsPoint`,
// we apply the birational map to obtain the Edwards y coordinate, then do Edwards decompression.
func DecodeMontgomeryPoint[T PointOperations](r *PublicKey[T], u *field.Element, sign int) *PublicKey[T] {
	if u == nil || u.Equal(_NEGATIVE_ONE) == 1 {
		return nil
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
		return nil
	}
	return r
}

// DecodeCompressedPoint Decompress a canonically-encoded Ed25519 point.
// Equivalent to Monero's check_key
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
func DecodeCompressedPoint[T PointOperations, S ~[PublicKeySize]byte](r *PublicKey[T], buf S) *PublicKey[T] {
	if r == nil {
		return nil
	}

	if _, err := r.SetBytes(buf[:]); err != nil {
		return nil
	}
	return r
}

func elementFromUint64(x uint64) *field.Element {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], x)

	e, err := new(field.Element).SetBytes(b[:])
	if err != nil {
		panic(err)
	}
	return e
}

var (
	_ONE          = new(field.Element).One()
	_NEGATIVE_ONE = new(field.Element).Negate(_ONE)

	// _MontgomeryA is equal to 486662, which is a constant of the curve equation for Curve25519 in its Montgomery form.
	_MontgomeryA         = elementFromUint64(486662)
	_MontgomeryNegativeA = new(field.Element).Negate(_MontgomeryA)
)
