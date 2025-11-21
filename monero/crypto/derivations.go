package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func GetDerivationSharedDataForOutputIndex(k *curve25519.Scalar, derivation curve25519.PublicKeyBytes, outputIndex uint64) *curve25519.Scalar {
	var varIntBuf [binary.MaxVarintLen64]byte
	return ScalarDeriveLegacy(k, derivation[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)])
}

var viewTagDomain = []byte("view_tag")

func GetDerivationViewTagForOutputIndex(derivation curve25519.PublicKeyBytes, outputIndex uint64) uint8 {
	var varIntBuf [binary.MaxVarintLen64]byte
	return Keccak256Var(viewTagDomain, derivation[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)])[0]
}

func GetDerivationSharedDataAndViewTagForOutputIndex(k *curve25519.Scalar, derivation curve25519.PublicKeyBytes, outputIndex uint64) (*curve25519.Scalar, uint8) {
	var varIntBuf [binary.MaxVarintLen64]byte

	n := binary.PutUvarint(varIntBuf[:], outputIndex)
	pK := ScalarDeriveLegacy(k, derivation[:], varIntBuf[:n])
	return pK, Keccak256Var(viewTagDomain, derivation[:], varIntBuf[:n])[0]
}

func GetKeyImage[T curve25519.PointOperations](out *curve25519.PublicKey[T], pair *KeyPair[T]) *curve25519.PublicKey[T] {
	hP := BiasedHashToPoint(out, pair.PublicKey.Bytes())
	hP.ScalarMult(&pair.PrivateKey, hP)
	return hP
}

// SecretDeriveN As defined in Carrot = SecretDerive(x) = H_n(x)
func SecretDeriveN[S ~[]byte](dst S, key []byte, data []byte, args ...[]byte) {
	var hasher blake2b.Digest
	_ = hasher.Init(len(dst), key, nil, nil)
	_, _ = utils.WriteNoEscape(&hasher, data)
	for _, b := range args {
		_, _ = utils.WriteNoEscape(&hasher, b)
	}

	utils.SumNoEscape(&hasher, dst[:0])
}

// SecretDerive As defined in Carrot = SecretDerive(x) = H_32(x)
func SecretDerive(key []byte, data ...[]byte) types.Hash {
	var hasher blake2b.Digest
	_ = hasher.Init(blake2b.Size256, key, nil, nil)
	for _, b := range data {
		_, _ = utils.WriteNoEscape(&hasher, b)
	}
	var h types.Hash
	utils.SumNoEscape(&hasher, h[:0])

	return h
}

// ScalarDerive As defined in Carrot = BytesToInt512(H_64(x)) mod ℓ
func ScalarDerive(c *curve25519.Scalar, key []byte, data ...[]byte) *curve25519.Scalar {
	hasher, _ := blake2b.New512(key)
	for _, b := range data {
		_, _ = utils.WriteNoEscape(hasher, b)
	}
	var h [blake2b.Size]byte
	utils.SumNoEscape(hasher, h[:0])

	curve25519.BytesToScalar64(c, h)

	return c
}

// ScalarDeriveLegacy As defined in Carrot = BytesToInt256(Keccak256(x)) mod ℓ
// Equivalent to hash_to_scalar
func ScalarDeriveLegacy(c *curve25519.Scalar, data ...[]byte) *curve25519.Scalar {
	h := Keccak256Var(data...)

	curve25519.BytesToScalar32(c, h)

	return c
}
