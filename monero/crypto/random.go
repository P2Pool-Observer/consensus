package crypto

import (
	"crypto/rand"
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

func RandomScalar() *edwards25519.Scalar {
	var buf [32]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return nil
		}

		if !IsReduced32(buf) {
			continue
		}

		scalar, _ := GetEdwards25519Scalar().SetCanonicalBytes(buf[:])
		if scalar.Equal(zeroScalar) == 0 {
			return scalar
		}
	}
}

// DeterministicScalar consensus way of generating a deterministic scalar from given entropy
// Slice entropy will have data appended
func DeterministicScalar(entropy []byte) *edwards25519.Scalar {

	var counter uint32

	n := len(entropy)

	entropy = append(entropy, 0, 0, 0, 0)

	h := GetKeccak256Hasher()
	defer PutKeccak256Hasher(h)
	var hash types.Hash

	scalar := GetEdwards25519Scalar()

	for {
		h.Reset()
		counter++
		binary.LittleEndian.PutUint32(entropy[n:], counter)
		_, _ = h.Write(entropy)
		HashFastSum(h, hash[:])
		if !IsLimit32(hash) {
			continue
		}
		BytesToScalar32(hash, scalar)

		if scalar.Equal(zeroScalar) == 0 {
			return scalar
		}
	}
}
