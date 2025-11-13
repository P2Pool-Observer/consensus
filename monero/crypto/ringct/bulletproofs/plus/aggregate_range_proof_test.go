package plus

import (
	"encoding/binary"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
)

func TestAggregateRangeProof(t *testing.T) {
	rng := crypto.NewDeterministicTestGenerator()
	_ = rng

	var verifier BatchVerifier[curve25519.VarTimeOperations]

	//for m := 1; m <= 16; m++ {
	for m := 1; m <= 1; m++ {
		var commitments []ringct.Commitment
		var mask curve25519.Scalar
		var amount [8]byte
		for range m {
			//curve25519.RandomScalar(&mask, rng)
			//_, _ = rng.Read(amount[:])
			mask = *(&curve25519.PrivateKeyBytes{byte(m)}).Scalar()
			amount[0] = byte(m) + 100
			//_, _ = rng.Read(amount[:])

			commitments = append(commitments, ringct.Commitment{
				Mask:   mask,
				Amount: binary.LittleEndian.Uint64(amount[:]),
			})
		}

		var commitmentPoints []curve25519.VarTimePublicKey

		for i := range commitments {
			commitmentPoints = append(commitmentPoints, *ringct.CalculateCommitment(new(curve25519.VarTimePublicKey), commitments[i]))
		}

		ars := AggregateRangeStatement[curve25519.VarTimeOperations]{
			V: commitmentPoints,
		}

		arw := AggregateRangeWitness(commitments)

		proof, err := ars.Prove(arw, rng)
		if err != nil {
			t.Fatal(err)
		}

		if !ars.Verify(&verifier, &proof, rng) {
			t.Fatal("aggregate range proof verify failed")
		}
	}

	if !verifier.Verify() {
		t.Fatal("batch verify failed")
	}
}
