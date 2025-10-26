package crypto

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"

type KeyPair[T curve25519.PointOperations] struct {
	PrivateKey curve25519.Scalar
	PublicKey  curve25519.PublicKey[T]
}

func NewKeyPairFromPrivate[T curve25519.PointOperations](privateKey *curve25519.Scalar) *KeyPair[T] {
	k := &KeyPair[T]{}
	k.PrivateKey.Set(privateKey)
	k.PublicKey.ScalarBaseMult(privateKey)
	return k
}
