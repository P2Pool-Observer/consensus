package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
)

func RctCommit(dst *PublicKeyPoint, amount uint64, mask *PrivateKeyScalar) {
	rctGenC(dst, mask, amount)
}

// rctGenC generates C =aG + bH from b, a is given..
func rctGenC(dst *PublicKeyPoint, a *PrivateKeyScalar, amount uint64) {
	var amountK PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountK[:], amount)
	dst.Point().VarTimeDoubleScalarBaseMult(amountK.AsScalar().Scalar(), GeneratorH, a.Scalar())
}

type RCTAmount struct {
	Encrypted  [monero.EncryptedAmountSize]byte
	Commitment PublicKeyBytes
}
