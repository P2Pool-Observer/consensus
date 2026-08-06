package helioselene

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/helioselene/helios" //nolint:depguard
	"git.gammaspectra.live/P2Pool/helioselene/selene" //nolint:depguard
)

type HeliosPoint = helios.Point
type SelenePoint = selene.Point

type VarTimeHeliosPoint = curve.VarTimePoint[HeliosPoint, HeliosScalar, *HeliosPoint, *HeliosScalar]
type VarTimeSelenePoint = curve.VarTimePoint[SelenePoint, SeleneScalar, *SelenePoint, *SeleneScalar]

type Point interface {
	HeliosPoint | SelenePoint
}

type Scalar interface { //nolint:iface
	HeliosScalar | SeleneScalar
}

type Field interface { //nolint:iface
	HeliosField | SeleneField
}

type CurvePointWithAffine[P Point, S Scalar, F Field] interface {
	curve.ExtraCurvePoint[P, S]
	PointWithAffine[P, F]
}

type PointWithAffine[P Point, F Field] interface {
	curve.Point[P]

	SetXY(x, y *F) (*P, error)
	XY() (x, y F, err error)
}
