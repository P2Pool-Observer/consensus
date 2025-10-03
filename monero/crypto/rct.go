package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/edwards25519"
)

func RctCommit(amount uint64, mask PrivateKey) PublicKey {
	return rctGenC(mask, amount)
}

// rctGenC generates C =aG + bH from b, a is given..
func rctGenC(a PrivateKey, amount uint64) PublicKey {
	var amountK PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountK[:], amount)
	return RctAddKeys2(a, &amountK, PublicKeyFromPoint(GeneratorH))
}

// TODO: rewrite
func RctAddKeys2(a, b PrivateKey, B PublicKey) PublicKey {
	return PublicKeyFromPoint(new(edwards25519.Point).VarTimeDoubleScalarBaseMult(b.AsScalar().Scalar(), B.AsPoint().Point(), a.AsScalar().Scalar()))
}
