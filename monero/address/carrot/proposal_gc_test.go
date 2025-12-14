//go:build gc && !tinygo

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
)

func BenchmarkPaymentProposalV1_OutputPartial(b *testing.B) {
	prop := &PaymentProposalV1[curve25519.VarTimeCounterOperations]{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(testSubaddress.PackedAddress(), false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     testAmount,
		Randomness: testAnchorNorm,
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
		Amount:     testAmount,
		Randomness: testAnchorNorm,
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
		Amount:     testAmount,
		Randomness: testAnchorNorm,
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
