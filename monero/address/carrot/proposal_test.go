package carrot

import (
	"math"
	unsafeRandom "math/rand/v2"
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

func TestPaymentProposalV1_CoinbaseOutput(t *testing.T) {
	expectedEnote := CoinbaseEnoteV1{
		OneTimeAddress:  types.MustBytes32FromString[curve25519.PublicKeyBytes]("661d4466f94d96d598ac983ed51f4f082aeb51045752c1bf8275f903bd090d79"),
		Amount:          monero.TailEmissionReward,
		EncryptedAnchor: types.MakeFixed([monero.JanusAnchorSize]byte(hex.MustDecodeString("e1654ef76f418d7357e45ba601c086a1"))),
		ViewTag:         types.MakeFixed([monero.CarrotViewTagSize]byte(hex.MustDecodeString("6bdfa1"))),
		EphemeralPubKey: types.MustBytes32FromString[curve25519.MontgomeryPoint]("ca85a5dba8a672974ac0b80a9d0b5eebf3a9ec8e2f2d4366152a6edb5facc232"),
		BlockIndex:      123456,
	}

	proposal := &PaymentProposalV1[curve25519.VarTimeOperations]{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(testSubaddress.PackedAddress(), false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: testRandomness,
	}

	var enote CoinbaseEnoteV1
	err := proposal.CoinbaseOutput(&enote, 123456)
	if err != nil {
		t.Fatalf("failed to generate coinbase enote: %s", err)
	}

	if expectedEnote != enote {
		t.Fatalf("coinbase enote does not match expected enote: expected %+v, got %+v", expectedEnote, enote)
	}
}

func BenchmarkPaymentProposalV1_OutputPartial(b *testing.B) {
	prop := &PaymentProposalV1[curve25519.VarTimeCounterOperations]{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(testSubaddress.PackedAddress(), false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: testRandomness,
	}

	b.Run("TorsionChecked", func(b *testing.B) {
		curve25519.VarTimeCounterOperationsReset()
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			proposal := *prop

			i := unsafeRandom.Uint64N(math.MaxUint32)
			var hasher blake2b.Digest
			for pb.Next() {
				i++
				proposal.torsionChecked = false
				inputContext := MakeCoinbaseInputContext(i)
				_, _, _, err := proposal.OutputPartial(&hasher, inputContext[:], true)
				if err != nil {
					b.Fatalf("failed to generate coinbase enote partial: %s", err)
				}
			}
		})

		b.StopTimer()
		curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
	})

	b.Run("TorsionUnchecked", func(b *testing.B) {
		curve25519.VarTimeCounterOperationsReset()
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			proposal := *prop

			i := unsafeRandom.Uint64N(math.MaxUint32)
			var hasher blake2b.Digest
			for pb.Next() {
				i++
				proposal.torsionChecked = true
				inputContext := MakeCoinbaseInputContext(i)
				_, _, _, err := proposal.OutputPartial(&hasher, inputContext[:], true)
				if err != nil {
					b.Fatalf("failed to generate coinbase enote partial: %s", err)
				}
			}
		})

		b.StopTimer()
		curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
	})

}

func BenchmarkPaymentProposalV1_CoinbaseOutput(b *testing.B) {
	prop := &PaymentProposalV1[curve25519.VarTimeCounterOperations]{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(testSubaddress.PackedAddress(), false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55")),
	}

	b.Run("TorsionChecked", func(b *testing.B) {
		curve25519.VarTimeCounterOperationsReset()
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			proposal := *prop

			var enote CoinbaseEnoteV1
			i := unsafeRandom.Uint64N(math.MaxUint32)
			for pb.Next() {
				i++
				proposal.torsionChecked = false
				err := proposal.CoinbaseOutput(&enote, i)
				if err != nil {
					b.Fatalf("failed to generate coinbase enote: %s", err)
				}
			}
		})

		b.StopTimer()
		curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
	})

	b.Run("TorsionUnchecked", func(b *testing.B) {
		curve25519.VarTimeCounterOperationsReset()
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			proposal := *prop

			var enote CoinbaseEnoteV1
			i := unsafeRandom.Uint64N(math.MaxUint32)
			for pb.Next() {
				i++
				proposal.torsionChecked = true
				err := proposal.CoinbaseOutput(&enote, i)
				if err != nil {
					b.Fatalf("failed to generate coinbase enote: %s", err)
				}
			}
		})

		b.StopTimer()
		curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
	})
}

func BenchmarkPaymentProposalV1_Output(b *testing.B) {
	firstKeyImage := types.MustBytes32FromString[curve25519.PublicKeyBytes]("a3d1d782671a3622bf393fe8116c8df95e9e12776e2970ab1934645f40748343")
	prop := &PaymentProposalV1[curve25519.VarTimeCounterOperations]{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(testSubaddress.PackedAddress(), true),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: testRandomness,
	}

	b.Run("TorsionChecked", func(b *testing.B) {
		curve25519.VarTimeCounterOperationsReset()
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			proposal := *prop

			var out RCTEnoteProposal
			i := unsafeRandom.Uint64N(math.MaxUint32)
			for pb.Next() {
				i++
				proposal.torsionChecked = false
				err := proposal.Output(&out, firstKeyImage)
				if err != nil {
					b.Fatalf("failed to generate coinbase enote: %s", err)
				}
			}
		})

		b.StopTimer()
		curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
	})

	b.Run("TorsionUnchecked", func(b *testing.B) {
		curve25519.VarTimeCounterOperationsReset()
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			proposal := *prop

			var out RCTEnoteProposal
			i := unsafeRandom.Uint64N(math.MaxUint32)
			for pb.Next() {
				i++
				proposal.torsionChecked = true
				err := proposal.Output(&out, firstKeyImage)
				if err != nil {
					b.Fatalf("failed to generate coinbase enote: %s", err)
				}
			}
		})

		b.StopTimer()
		curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
	})
}
