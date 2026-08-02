package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/edwards25519" //nolint:depguard
)

var infinityPoint = edwards25519.NewIdentityPoint()
var zeroScalar = new(curve25519.Scalar).Zero()
