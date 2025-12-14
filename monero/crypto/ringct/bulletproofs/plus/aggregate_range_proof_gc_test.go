//go:build gc && !tinygo

package plus

import (
	"encoding/binary"
	"fmt"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
)

func BenchmarkAggregateRangeProofProve(b *testing.B) {

	for m := 1; m <= 16; m++ {
		b.Run(fmt.Sprintf("#%d", m), func(b *testing.B) {
			b.ReportAllocs()

			rng := crypto.NewDeterministicTestGenerator()

			var commitments []ringct.LazyCommitment
			var mask curve25519.Scalar
			var amount [8]byte
			for range m {
				curve25519.RandomScalar(&mask, rng)
				_, _ = rng.Read(amount[:])

				commitments = append(commitments, ringct.LazyCommitment{
					Mask:   mask,
					Amount: binary.LittleEndian.Uint64(amount[:]),
				})
			}

			var commitmentPoints []curve25519.PublicKey[curve25519.VarTimeCounterOperations]

			for i := range commitments {
				commitmentPoints = append(commitmentPoints, *ringct.CalculateCommitment(new(curve25519.PublicKey[curve25519.VarTimeCounterOperations]), commitments[i]))
			}

			ars := AggregateRangeStatement[curve25519.VarTimeCounterOperations]{
				V: commitmentPoints,
			}

			arw := AggregateRangeWitness(commitments)

			curve25519.VarTimeCounterOperationsReset()

			for b.Loop() {
				proof, err := ars.Prove(arw, rng)
				if err != nil {
					b.Fatal(err)
				}
				_ = proof
			}
			b.StopTimer()
			curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
		})

	}
}
