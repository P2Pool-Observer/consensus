package curve25519

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/edwards25519/field" //nolint:depguard
)

type Ciphersuite struct{}

func (c Ciphersuite) A() *field.Element {
	return _WeiA
}

func (c Ciphersuite) B() *field.Element {
	return _WeiB
}

func (c Ciphersuite) Generator() *Point {
	return generator
}

func (c Ciphersuite) ScalarBits() int {
	return 253
}

func (c Ciphersuite) InterpolatorForScalarMulDegree() int {
	return 128
}

func (c Ciphersuite) XY(v *Point) (x, y field.Element, err error) {
	return v.XY()
}

// a = (3 - A^2) / 3
var _WeiA = new(field.Element).Multiply(
	new(field.Element).Subtract(
		curve.FieldFromUint64(new(field.Element), 3),
		new(field.Element).Square(_A),
	),
	new(field.Element).Invert(curve.FieldFromUint64(new(field.Element), 3)),
)

// b = (2A^3 - 9A) / 27
var _WeiB = new(field.Element).Multiply(
	new(field.Element).Subtract(
		new(field.Element).Multiply(
			curve.FieldFromUint64(new(field.Element), 2),
			new(field.Element).Multiply(_A, new(field.Element).Square(_A)), // A^3
		),
		new(field.Element).Multiply(curve.FieldFromUint64(new(field.Element), 9), _A),
	),
	new(field.Element).Invert(curve.FieldFromUint64(new(field.Element), 27)),
)
