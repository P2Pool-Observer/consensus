package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

var infinityPoint = curve25519.NewIdentityPoint()
var zeroScalar = new(curve25519.Scalar).Zero()
