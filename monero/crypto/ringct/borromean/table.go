package borromean

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

// generatorHPow2 Monero's `H` generator, multiplied by 2**i for i in 1 ..= 64.
var generatorHPow2 [Elements]*curve25519.Point

//nolint:gochecknoinits
func init() {
	generatorHPow2[0] = crypto.GeneratorH.Point
	for i := range generatorHPow2[1:] {
		generatorHPow2[i+1] = new(curve25519.Point).Add(generatorHPow2[i], generatorHPow2[i])
	}
}
