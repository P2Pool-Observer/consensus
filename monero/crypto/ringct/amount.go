package ringct

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

// Commit generates C =aG + bH from b, a is mask
func Commit[T curve25519.PointOperations](dst *curve25519.PublicKey[T], amount uint64, mask *curve25519.Scalar) {
	var amountBytes curve25519.PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountBytes[:], amount)

	// no reduction is necessary: amountBytes is always lesser than l
	var amountK curve25519.Scalar
	_, _ = amountK.SetCanonicalBytes(amountBytes[:])

	dst.DoubleScalarBaseMultPrecomputed(&amountK, crypto.GeneratorH, mask)
}

type Amount struct {
	Encrypted  [monero.EncryptedAmountSize]byte
	Commitment curve25519.PublicKeyBytes
}

var encryptedAmountKey = []byte("amount")

// DecryptOutputAmount Decrypts or encrypts an amount field from ECDH Info
func DecryptOutputAmount(k curve25519.PrivateKeyBytes, ciphertext uint64) uint64 {
	var key [monero.EncryptedAmountSize]byte
	h := crypto.NewKeccak256()
	_, _ = h.Write(encryptedAmountKey)
	_, _ = h.Write(k[:])
	_, _ = h.Read(key[:])
	return ciphertext ^ binary.LittleEndian.Uint64(key[:])
}
