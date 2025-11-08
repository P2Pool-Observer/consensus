package bulletproofs

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

// MaxCommitments The maximum amount of commitments provable for within a single Bulletproof(+).
const MaxCommitments = 16

// CommitmentBits The amount of bits a value within a commitment may use.
const CommitmentBits = 64

type Generators struct {
	G []*curve25519.Point
	H []*curve25519.Point
}

var Generator = initGenerators[curve25519.VarTimeOperations]("bulletproof")
var GeneratorPlus = initGenerators[curve25519.VarTimeOperations]("bulletproof_plus")

func initGenerators[T1 curve25519.PointOperations, T2 string | []byte](prefix T2) (g Generators) {
	const size = MaxCommitments * CommitmentBits

	preimage := crypto.GeneratorH.Point.Bytes()
	preimage = append(preimage, prefix...)

	g.G = make([]*curve25519.Point, size)
	g.H = make([]*curve25519.Point, size)

	for i := range size {
		i = 2 * i
		preimage = binary.AppendUvarint(preimage, uint64(i))
		// yep, double hash
		h := crypto.Keccak256(preimage)
		g.H[i/2] = crypto.BiasedHashToPoint(new(curve25519.PublicKey[T1]), h[:]).P()
		preimage = preimage[:len(prefix)+curve25519.PublicKeySize]

		preimage = binary.AppendUvarint(preimage, uint64(i+1))
		h = crypto.Keccak256(preimage)
		g.G[i/2] = crypto.BiasedHashToPoint(new(curve25519.PublicKey[T1]), h[:]).P()
		preimage = preimage[:len(prefix)+curve25519.PublicKeySize]
	}
	return g
}
