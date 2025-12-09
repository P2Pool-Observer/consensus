package crypto

import (
	"crypto/rand"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"golang.org/x/crypto/chacha20"
)

func generateChaChaKey(data []byte, kdfRounds int, prehashed bool) types.Hash {
	var state cryptonight.State
	pwdHash := state.Sum(data, 0, prehashed)
	for i := 1; i < kdfRounds; i++ {
		pwdHash = state.Sum(pwdHash[:], 0, false)
	}
	return pwdHash
}

const ChaChaNonceSize = chacha20.NonceSize - 4

func ChaChaEncrypt(dst, src []byte, secretKey []byte, kdfRounds int) {
	if len(dst) != len(src)+ChaChaNonceSize {
		panic("chacha20: buffer size mismatch")
	}
	key := generateChaChaKey(secretKey, kdfRounds, false)

	var iv [chacha20.NonceSize]byte
	_, _ = rand.Read(iv[4:])

	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], iv[:])
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(dst[ChaChaNonceSize:], src)
	copy(dst, iv[4:])
}

func ChaChaDecrypt(dst, src []byte, secretKey []byte, kdfRounds int) {
	if len(dst) != len(src)-ChaChaNonceSize {
		panic("chacha20: buffer size mismatch")
	}
	key := generateChaChaKey(secretKey, kdfRounds, false)

	var iv [chacha20.NonceSize]byte
	copy(iv[4:], src)

	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], iv[:])
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(dst, src[ChaChaNonceSize:])
}
