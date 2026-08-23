package helioselene

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/helioselene/helios" //nolint:depguard
	"git.gammaspectra.live/P2Pool/helioselene/selene" //nolint:depguard
)

type HeliosParams struct {
	a HeliosField
}

func (p *HeliosParams) A() *HeliosField {
	return &p.a
}

func (p *HeliosParams) B() *HeliosField {
	return helios.B
}

func (p *HeliosParams) Generator() *HeliosPoint {
	return helios.G
}

func (p *HeliosParams) ScalarBits() int {
	return 255
}

func (p *HeliosParams) XY(v *HeliosPoint) (x, y HeliosField, err error) {
	return v.XY()
}

var HeliosCiphersuite = &HeliosParams{
	a: *new(HeliosField).Negate(curve.ScalarFromUint64(new(HeliosField), 3)),
}

type SeleneParams struct {
	a SeleneField
}

func (p *SeleneParams) A() *SeleneField {
	return &p.a
}

func (p *SeleneParams) B() *SeleneField {
	return selene.B
}

func (p *SeleneParams) Generator() *SelenePoint {
	return selene.G
}

func (p *SeleneParams) ScalarBits() int {
	return 255
}

func (p *SeleneParams) XY(v *SelenePoint) (x, y SeleneField, err error) {
	return v.XY()
}

var SeleneCiphersuite = &SeleneParams{
	a: *new(SeleneField).Negate(curve.ScalarFromUint64(new(SeleneField), 3)),
}
