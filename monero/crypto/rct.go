package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

// RctCommit generates C =aG + bH from b, a is mask
func RctCommit(dst *PublicKeyPoint, amount uint64, mask *PrivateKeyScalar) {
	var amountBytes PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountBytes[:], amount)

	// no reduction is necessary: amountBytes is always lesser than l
	var amountK edwards25519.Scalar
	_, _ = amountK.SetCanonicalBytes(amountBytes[:])

	dst.Point().UnsafeVarTimeDoubleScalarBaseMultPrecomputed(&amountK, GeneratorH.Table, mask.Scalar())
}

type RCTAmount struct {
	Encrypted  [monero.EncryptedAmountSize]byte
	Commitment PublicKeyBytes
}
