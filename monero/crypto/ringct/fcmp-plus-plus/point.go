package fcmp_plus_plus

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/helioselene"
)

type Point interface {
	helioselene.Point | curve25519.Point | curve25519.ConstantTimePublicKey | curve25519.VarTimePublicKey
}

type Scalar interface {
	helioselene.Scalar | curve25519.Scalar
}

type Field interface {
	helioselene.Field
}
