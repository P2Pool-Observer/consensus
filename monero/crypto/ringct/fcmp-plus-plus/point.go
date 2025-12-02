package fcmp_plus_plus

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"

type HSPoint[P any, S any, F any, VF curve.Field[F]] interface {
	curve.ExtraCurvePoint[P, S]
	XY() (x F, y F, err error)
	SetXY(x, y *F) (*P, error)
}
