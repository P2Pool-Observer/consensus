package ringct

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

func AmountToScalar(out *curve25519.Scalar, amount uint64) *curve25519.Scalar {
	// no reduction is necessary: amountBytes is always lesser than l
	var amountBytes curve25519.PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountBytes[:], amount)
	_, _ = out.SetCanonicalBytes(amountBytes[:])
	return out
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
