package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

// RctCommit generates C =aG + bH from b, a is mask
func RctCommit[T curve25519.PointOperations](dst *curve25519.PublicKey[T], amount uint64, mask *curve25519.Scalar) {
	var amountBytes curve25519.PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountBytes[:], amount)

	// no reduction is necessary: amountBytes is always lesser than l
	var amountK edwards25519.Scalar
	_, _ = amountK.SetCanonicalBytes(amountBytes[:])

	dst.DoubleScalarBaseMultPrecomputed(&amountK, GeneratorH, mask)
}

type RCTAmount struct {
	Encrypted  [monero.EncryptedAmountSize]byte
	Commitment curve25519.PublicKeyBytes
}
