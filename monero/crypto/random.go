package crypto

import (
	"crypto/rand"
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
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

		scalar, _ := new(edwards25519.Scalar).SetCanonicalBytes(buf[:])
		if scalar.Equal(zeroScalar) == 0 {
			return scalar
		}
	}
}

// DeterministicScalar consensus way of generating a deterministic scalar from given entropy
func DeterministicScalar(entropy []byte) *edwards25519.Scalar {

	var counter uint32
	var nonce [4]byte

	h := newKeccak256()
	var hash types.Hash

	scalar := new(edwards25519.Scalar)

	for {
		counter++
		binary.LittleEndian.PutUint32(nonce[:], counter)
		_, _ = utils.WriteNoEscape(h, entropy)
		_, _ = utils.WriteNoEscape(h, nonce[:])
		_, _ = utils.ReadNoEscape(h, hash[:])
		if !IsLimit32(hash) {
			utils.ResetNoEscape(h)
			continue
		}
		BytesToScalar32(hash, scalar)

		if scalar.Equal(zeroScalar) == 0 {
			return scalar
		}
		utils.ResetNoEscape(h)
	}
}
