package fcmp_plus_plus

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"

type HSPoint[P any, F any, VF curve.Field[F]] interface {
	curve.CurvePoint[P, F]
	XY() (F, F, error)
	SetXY(*F, *F) (*P, error)
}
