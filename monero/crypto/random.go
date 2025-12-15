package crypto

import (
	"crypto/subtle"
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/sha3"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"

	// required for go:linkname
	_ "unsafe"
)

// DeterministicScalar consensus way of generating a deterministic scalar from given entropy
func DeterministicScalar(k *curve25519.Scalar, entropy []byte) *curve25519.Scalar {

	var counter uint32
	var nonce [4]byte

	h := NewKeccak256()
	var hash types.Hash

	for {
		counter++
		binary.LittleEndian.PutUint32(nonce[:], counter)
		_, _ = utils.WriteNoEscape(h, entropy)
		_, _ = utils.WriteNoEscape(h, nonce[:])
		_, _ = utils.ReadNoEscape(h, hash[:])
		if !curve25519.ScalarIsLimit32(hash) {
			utils.ResetNoEscape(h)
			continue
		}
		curve25519.BytesToScalar32(k, hash)

		if k.Equal(zeroScalar) == 0 {
			return k
		}
		utils.ResetNoEscape(h)
	}
}

const rateK512 = (1600 - 512) / 8

// DeterministicTestGenerator Implements a deterministic generator as written on Monero's random.c
// Useful for passing tests
type DeterministicTestGenerator struct {
	state        [1600 / 8]byte
	permutations int
}

func NewDeterministicTestGenerator() *DeterministicTestGenerator {
	g := &DeterministicTestGenerator{}
	for i := range g.state {
		g.state[i] = 42
	}
	return g
}

func (g *DeterministicTestGenerator) permute() {
	sha3.KeccakF1600(&g.state)
	g.permutations++
}

func (g *DeterministicTestGenerator) Permutations() int {
	return g.permutations
}

func (g *DeterministicTestGenerator) Size() int {
	return len(g.state)
}

func (g *DeterministicTestGenerator) Init(buf []byte) {
	copy(g.state[:], buf)
}

func (g *DeterministicTestGenerator) Write(buf []byte) (n int, err error) {
	for len(buf) > 0 {
		g.permute()
		subtle.XORBytes(g.state[:rateK512], g.state[:rateK512], buf)
		if len(buf) <= rateK512 {
			n += len(buf)
			return n, nil
		} else {
			buf = buf[rateK512:]
			n += rateK512
		}
	}

	return n, nil
}

func (g *DeterministicTestGenerator) Skip(n int) {
	for range n {
		g.permute()
	}
}

func (g *DeterministicTestGenerator) Read(buf []byte) (n int, err error) {
	for len(buf) > 0 {
		g.permute()
		copy(buf, g.state[:rateK512])

		if len(buf) <= rateK512 {
			n += len(buf)
			return n, nil
		} else {
			buf = buf[rateK512:]
			n += rateK512
		}
	}
	return n, nil
}
