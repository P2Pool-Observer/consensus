package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

func GetDerivationSharedDataForOutputIndex(derivation PublicKey, outputIndex uint64) PrivateKey {
	var k = derivation.AsBytes()
	var varIntBuf [binary.MaxVarintLen64]byte
	return PrivateKeyFromScalar(ScalarDeriveLegacy(k[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)]))
}

var viewTagDomain = []byte("view_tag")

func GetDerivationViewTagForOutputIndex(derivation PublicKey, outputIndex uint64) uint8 {
	var k = derivation.AsBytes()
	var varIntBuf [binary.MaxVarintLen64]byte
	return Keccak256Var(viewTagDomain, k[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)])[0]
}

func GetDerivationSharedDataAndViewTagForOutputIndex(derivation PublicKey, outputIndex uint64) (PrivateKey, uint8) {
	var k = derivation.AsBytes()
	var varIntBuf [binary.MaxVarintLen64]byte

	n := binary.PutUvarint(varIntBuf[:], outputIndex)
	pK := PrivateKeyFromScalar(ScalarDeriveLegacy(k[:], varIntBuf[:n]))
	return pK, Keccak256Var(viewTagDomain, k[:], varIntBuf[:n])[0]
}

var encryptedAmountKey = []byte("amount")

// DecryptOutputAmount Decrypts an encrypted amount field from ECDH Info
func DecryptOutputAmount(k PrivateKey, ciphertext uint64) uint64 {
	var key [8]byte
	h := newKeccak256()
	_, _ = utils.WriteNoEscape(h, encryptedAmountKey)
	_, _ = utils.WriteNoEscape(h, k.AsSlice())
	_, _ = utils.ReadNoEscape(h, key[:])
	return ciphertext ^ binary.LittleEndian.Uint64(key[:])
}

// GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate Special version of GetDerivationSharedDataAndViewTagForOutputIndex
func GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(dst *edwards25519.Scalar, k PublicKeyBytes, outputIndex uint64) (viewTag uint8) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], outputIndex)
	h := Keccak256Var(k[:], buf[:n])
	BytesToScalar32(h, dst)

	h = Keccak256Var(viewTagDomain, k[:], buf[:n])

	return h[0]
}

func GetKeyImage(pair *KeyPair) PublicKey {
	return PublicKeyFromPoint(BiasedHashToPoint(new(edwards25519.Point), pair.PublicKey.AsSlice())).Multiply(pair.PrivateKey.AsScalar())
}

// SecretDeriveN As defined in Carrot = SecretDerive(x) = H_n(x)
func SecretDeriveN(n int, key []byte, data ...[]byte) []byte {
	hasher, _ := blake2b.New(n, key)
	if hasher == nil {
		panic("unreachable")
	}
	for _, b := range data {
		_, _ = utils.WriteNoEscape(hasher, b)
	}
	h := make([]byte, n)
	return utils.SumNoEscape(hasher, h[:0])
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
	BytesToScalar64(h, c)

	return c
}

// ScalarDeriveLegacy As defined in Carrot = BytesToInt256(Keccak256(x)) mod ℓ
func ScalarDeriveLegacy(data ...[]byte) *edwards25519.Scalar {
	h := Keccak256Var(data...)

	c := new(edwards25519.Scalar)
	BytesToScalar32(h, c)

	return c
}

func ScalarDeriveLegacyNoAllocate(c *edwards25519.Scalar, data ...[]byte) {
	h := Keccak256Var(data...)

	BytesToScalar32(h, c)
}
