package crypto

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/sha3"
)

func GetDerivationSharedDataForOutputIndex(derivation PublicKey, outputIndex uint64) PrivateKey {
	var k = derivation.AsBytes()
	var varIntBuf [binary.MaxVarintLen64]byte
	return PrivateKeyFromScalar(HashToScalar(k[:], varIntBuf[:binary.PutUvarint(varIntBuf[:], outputIndex)]))
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
	pK := PrivateKeyFromScalar(HashToScalar(k[:], varIntBuf[:n]))
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
	scReduce32(h[:])

	var c edwards25519.Scalar
	_, _ = c.SetCanonicalBytes(h[:])

	hasher.Reset()
	_, _ = hasher.Write(viewTagDomain)
	_, _ = hasher.Write(buf[:PublicKeySize+n])
	HashFastSum(hasher, h[:])

	return c, h[0]
}

/* TODO: wait for HashToPoint in edwards25519
func GetKeyImage(pair *KeyPair) PublicKey {
	return PublicKeyFromPoint(HashToPoint(pair.PublicKey)).Multiply(pair.PrivateKey.AsScalar())
}
*/
