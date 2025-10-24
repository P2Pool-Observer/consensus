package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

var generatorHPrecomputedTable = edwards25519.PointTablePrecompute(GeneratorH)

// RctCommit generates C =aG + bH from b, a is mask
func RctCommit(dst *PublicKeyPoint, amount uint64, mask *PrivateKeyScalar) {
	var amountK PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountK[:], amount)
	dst.Point().UnsafeVarTimeDoubleScalarBaseMultPrecomputed(amountK.AsScalar().Scalar(), generatorHPrecomputedTable, mask.Scalar())
}

// rctGenC
func rctGenC(dst *PublicKeyPoint, a *PrivateKeyScalar, amount uint64) {

}

type RCTAmount struct {
	Encrypted  [monero.EncryptedAmountSize]byte
	Commitment PublicKeyBytes
}
