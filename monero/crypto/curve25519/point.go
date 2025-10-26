package curve25519

import (
	"bytes"
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/edwards25519/field"
)

type Point = edwards25519.Point

// DecodeMontgomeryPoint
// Constant time
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

	var yBytes [32]byte
	copy(yBytes[:], y.Bytes())
	yBytes[31] ^= byte(sign << 7)

	return DecodeCompressedPoint(r, yBytes)
}

// DecodeCompressedPoint Decompress a canonically-encoded Ed25519 point.
//
// Ed25519 is of order `8 * basepointOrder`. This function ensures each of those `8 * basepointOrder` points have a
// singular encoding by checking points aren't encoded with an unreduced field element,
// and aren't negative when the negative is equivalent (0 == -0).
//
// Since this decodes an Ed25519 point, it does not check the point is in the prime-order
// subgroup. Torsioned points do have a canonical encoding, and only aren't canonical when
// considered in relation to the prime-order subgroup.
//
// To verify torsion use PublicKeyPoint.IsTorsionFree
func DecodeCompressedPoint[T PointOperations, S ~[PublicKeySize]byte](r *PublicKey[T], buf S) *PublicKey[T] {
	if r == nil {
		return nil
	}

	_, err := r.p.SetBytes(buf[:])
	if err != nil {
		return nil
	}

	// Ban points which are either unreduced or -0
	if bytes.Compare(r.p.Bytes(), buf[:]) != 0 {
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
	_A            = elementFromUint64(486662)
	_NEGATIVE_A   = new(field.Element).Negate(_A)
)
