package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/sha3"
	"golang.org/x/crypto/blake2b"
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
	return PooledKeccak256(viewTagDomain, k[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)])[0]
}

func GetDerivationSharedDataAndViewTagForOutputIndex(derivation PublicKey, outputIndex uint64) (PrivateKey, uint8) {
	var k = derivation.AsBytes()
	var varIntBuf [binary.MaxVarintLen64]byte

	n := binary.PutUvarint(varIntBuf[:], outputIndex)
	pK := PrivateKeyFromScalar(ScalarDeriveLegacy(k[:], varIntBuf[:n]))
	return pK, PooledKeccak256(viewTagDomain, k[:], varIntBuf[:n])[0]
}

var encryptedAmountKey = []byte("amount")

// DecryptOutputAmount Decrypts an encrypted amount field from ECDH Info
func DecryptOutputAmount(k PrivateKey, ciphertext uint64) uint64 {
	var key [8]byte
	h := GetKeccak256Hasher()
	defer PutKeccak256Hasher(h)
	_, _ = h.Write(encryptedAmountKey)
	_, _ = h.Write(k.AsSlice())
	_, _ = h.Read(key[:])
	return ciphertext ^ binary.LittleEndian.Uint64(key[:])
}

// GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate Special version of GetDerivationSharedDataAndViewTagForOutputIndex
func GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(k PublicKeyBytes, outputIndex uint64, hasher *sha3.HasherState) (edwards25519.Scalar, uint8) {
	var buf [PublicKeySize + binary.MaxVarintLen64]byte
	copy(buf[:], k[:])

	n := binary.PutUvarint(buf[PublicKeySize:], outputIndex)
	var h types.Hash
	hasher.Reset()
	_, _ = hasher.Write(buf[:PublicKeySize+n])
	HashFastSum(hasher, h[:])

	var c edwards25519.Scalar
	BytesToScalar32(h, &c)

	hasher.Reset()
	_, _ = hasher.Write(viewTagDomain)
	_, _ = hasher.Write(buf[:PublicKeySize+n])
	HashFastSum(hasher, h[:])

	return c, h[0]
}

func GetKeyImage(pair *KeyPair) PublicKey {
	return PublicKeyFromPoint(BiasedHashToPoint(pair.PublicKey.AsSlice())).Multiply(pair.PrivateKey.AsScalar())
}

// SecretDeriveN As defined in Carrot = SecretDerive(x) = H_n(x)
func SecretDeriveN(n int, key []byte, data ...[]byte) []byte {
	hasher, _ := blake2b.New(n, key)
	if hasher == nil {
		panic("unreachable")
	}
	for _, b := range data {
		_, _ = hasher.Write(b)
	}
	h := make([]byte, n)
	return hasher.Sum(h[:0])
}

// SecretDerive As defined in Carrot = SecretDerive(x) = H_32(x)
func SecretDerive(key []byte, data ...[]byte) types.Hash {
	hasher, _ := blake2b.New256(key)
	for _, b := range data {
		_, _ = hasher.Write(b)
	}
	var h types.Hash
	hasher.Sum(h[:0])

	return h
}

// ScalarDerive As defined in Carrot = BytesToInt512(H_64(x)) mod ℓ
func ScalarDerive(key []byte, data ...[]byte) *edwards25519.Scalar {
	hasher, _ := blake2b.New512(key)
	for _, b := range data {
		_, _ = hasher.Write(b)
	}
	var h [blake2b.Size]byte
	hasher.Sum(h[:0])

	c := GetEdwards25519Scalar()
	BytesToScalar64(h, c)

	return c
}

// ScalarDeriveLegacy As defined in Carrot = BytesToInt256(Keccak256(x)) mod ℓ
func ScalarDeriveLegacy(data ...[]byte) *edwards25519.Scalar {
	h := PooledKeccak256(data...)

	c := GetEdwards25519Scalar()
	BytesToScalar32(h, c)

	return c
}

func ScalarDeriveLegacyNoAllocate(c *edwards25519.Scalar, data ...[]byte) {
	h := Keccak256(data...)

	BytesToScalar32(h, c)
}
