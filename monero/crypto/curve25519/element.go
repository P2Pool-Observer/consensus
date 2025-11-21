package curve25519

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/edwards25519/field"
)

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
