package helioselene

import (
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
)

func pointToCycleScalar[P Point, F Field, FE curve.BasicField[F], PE PointWithAffine[P, F]](out *F, point *P) (scalar *F, err error) {
	if out == nil || point == nil {
		return nil, ErrInvalidParameter
	}

	x, _, err := PE(point).XY()
	if err != nil {
		return nil, errors.Join(ErrInvalidPoint, err)
	}

	return FE(out).Set(&x), nil
}

var ErrInvalidParameter = errors.New("invalid parameter")
var ErrInvalidPoint = errors.New("invalid point")

func SelenePointToHeliosScalar(out *HeliosScalar, point *SelenePoint) (*HeliosScalar, error) {
	return pointToCycleScalar(out, point)
}

func HeliosPointToSeleneScalar(out *SeleneScalar, point *HeliosPoint) (*SeleneScalar, error) {
	return pointToCycleScalar(out, point)
}
