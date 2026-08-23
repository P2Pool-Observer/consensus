package helioselene

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/helioselene/helios" //nolint:depguard
	"git.gammaspectra.live/P2Pool/helioselene/selene" //nolint:depguard
)

type HeliosCiphersuite struct{}

func (c HeliosCiphersuite) A() *HeliosField {
	return _heliosA
}

func (c HeliosCiphersuite) B() *HeliosField {
	return helios.B
}

func (c HeliosCiphersuite) Generator() *HeliosPoint {
	return helios.G
}

func (c HeliosCiphersuite) ScalarBits() int {
	return 255
}

func (c HeliosCiphersuite) InterpolatorForScalarMulDegree() int {
	return 130
}

func (c HeliosCiphersuite) XY(v *HeliosPoint) (x, y HeliosField, err error) {
	return v.XY()
}

var _heliosA = new(HeliosField).Negate(curve.ScalarFromUint64(new(HeliosField), 3))

type SeleneCiphersuite struct{}

func (c SeleneCiphersuite) A() *SeleneField {
	return _seleneA
}

func (c SeleneCiphersuite) B() *SeleneField {
	return selene.B
}

func (c SeleneCiphersuite) Generator() *SelenePoint {
	return selene.G
}

func (c SeleneCiphersuite) ScalarBits() int {
	return 255
}

func (c SeleneCiphersuite) InterpolatorForScalarMulDegree() int {
	return 130
}

func (c SeleneCiphersuite) XY(v *SelenePoint) (x, y SeleneField, err error) {
	return v.XY()
}

var _seleneA = new(SeleneField).Negate(curve.ScalarFromUint64(new(SeleneField), 3))
