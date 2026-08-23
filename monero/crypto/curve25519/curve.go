package curve25519

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/edwards25519/field" //nolint:depguard
)

type Params struct {
	a, b field.Element
}

func (p *Params) A() *field.Element {
	return &p.a
}

func (p *Params) B() *field.Element {
	return &p.b
}

func (p *Params) Generator() *Point {
	return generator
}

func (p *Params) ScalarBits() int {
	return 253
}

func (p *Params) XY(v *Point) (x, y field.Element, err error) {
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

var Ciphersuite = &Params{
	// Wei25519 a/b
	// https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-02.pdf E.3
	a: *_WeiA,
	b: *_WeiB,
}
