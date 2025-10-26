package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

func GetDerivationSharedDataForOutputIndex(k *curve25519.Scalar, derivation curve25519.PublicKeyBytes, outputIndex uint64) *curve25519.Scalar {
	var varIntBuf [binary.MaxVarintLen64]byte
	return ScalarDeriveLegacyNoAllocate(k, derivation[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)])
}

var viewTagDomain = []byte("view_tag")

func GetDerivationViewTagForOutputIndex(derivation curve25519.PublicKeyBytes, outputIndex uint64) uint8 {
	var varIntBuf [binary.MaxVarintLen64]byte
	return Keccak256Var(viewTagDomain, derivation[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)])[0]
}

func GetDerivationSharedDataAndViewTagForOutputIndex(k *curve25519.Scalar, derivation curve25519.PublicKeyBytes, outputIndex uint64) (*curve25519.Scalar, uint8) {
	var varIntBuf [binary.MaxVarintLen64]byte

	n := binary.PutUvarint(varIntBuf[:], outputIndex)
	pK := ScalarDeriveLegacyNoAllocate(k, derivation[:], varIntBuf[:n])
	return pK, Keccak256Var(viewTagDomain, derivation[:], varIntBuf[:n])[0]
}

var encryptedAmountKey = []byte("amount")

// DecryptOutputAmount Decrypts or encrypts an amount field from ECDH Info
func DecryptOutputAmount(k curve25519.PrivateKeyBytes, ciphertext uint64) uint64 {
	var key [8]byte
	h := newKeccak256()
	_, _ = utils.WriteNoEscape(h, encryptedAmountKey)
	_, _ = utils.WriteNoEscape(h, k[:])
	_, _ = utils.ReadNoEscape(h, key[:])
	return ciphertext ^ binary.LittleEndian.Uint64(key[:])
}

// GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate Special version of GetDerivationSharedDataAndViewTagForOutputIndex
func GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(dst *curve25519.Scalar, k curve25519.PublicKeyBytes, outputIndex uint64) (viewTag uint8) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], outputIndex)
	h := Keccak256Var(k[:], buf[:n])
	curve25519.BytesToScalar32(dst, h)

	h = Keccak256Var(viewTagDomain, k[:], buf[:n])

	return h[0]
}

func GetKeyImage[T curve25519.PointOperations](pair *KeyPair[T]) *curve25519.PublicKey[T] {
	hP := BiasedHashToPoint(new(curve25519.PublicKey[T]), pair.PublicKey.Slice())
	hP.ScalarMult(&pair.PrivateKey, hP)
	return hP
}

// SecretDeriveN As defined in Carrot = SecretDerive(x) = H_n(x)
func SecretDeriveN[S ~[]byte](dst S, key []byte, data []byte, args ...[]byte) {
	hasher, _ := blake2b.NewDigest(len(dst), key, nil, nil)
	if hasher == nil {
		panic("unreachable")
	}
	_, _ = hasher.Write(data)
	for _, b := range args {
		_, _ = hasher.Write(b)
	}

	hasher.Sum(dst[:0])
}

// SecretDerive As defined in Carrot = SecretDerive(x) = H_32(x)
func SecretDerive(key []byte, data ...[]byte) types.Hash {
	hasher, _ := blake2b.New256(key)
	for _, b := range data {
		_, _ = utils.WriteNoEscape(hasher, b)
	}
	var h types.Hash
	utils.SumNoEscape(hasher, h[:0])

	return h
}

// ScalarDerive As defined in Carrot = BytesToInt512(H_64(x)) mod ℓ
func ScalarDerive(key []byte, data ...[]byte) *edwards25519.Scalar {
	hasher, _ := blake2b.New512(key)
	for _, b := range data {
		_, _ = utils.WriteNoEscape(hasher, b)
	}
	var h [blake2b.Size]byte
	utils.SumNoEscape(hasher, h[:0])

	c := new(edwards25519.Scalar)
	curve25519.BytesToScalar64(c, h)

	return c
}

// ScalarDeriveLegacy As defined in Carrot = BytesToInt256(Keccak256(x)) mod ℓ
func ScalarDeriveLegacy(data ...[]byte) *edwards25519.Scalar {
	h := Keccak256Var(data...)

	c := new(edwards25519.Scalar)
	curve25519.BytesToScalar32(c, h)

	return c
}

func ScalarDeriveLegacyNoAllocate(c *edwards25519.Scalar, data ...[]byte) *edwards25519.Scalar {
	h := Keccak256Var(data...)

	curve25519.BytesToScalar32(c, h)

	return c
}
