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
		OneTimeAddress:  types.MustBytes32FromString[curve25519.PublicKeyBytes]("8519e0b836e249a2870b089402ee2bf8549cb91d237dee7768a3bfe1864151f2"),
		Amount:          testAmount,
		EncryptedAnchor: types.MakeFixed([monero.JanusAnchorSize]byte(hex.MustDecodeString("a0bab247eab215b31cb61d143c72bbe1"))),
		ViewTag:         types.MakeFixed([monero.CarrotViewTagSize]byte(hex.MustDecodeString("ecd398"))),
		EphemeralPubKey: types.MustBytes32FromString[curve25519.MontgomeryPoint]("f120a52046feb1e4fac770e97eb15568f8a86b67c8478e8816086dccdb6dcc2e"),
		BlockIndex:      123456,
	}

	proposal := &PaymentProposalV1[curve25519.VarTimeOperations]{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(testSubaddress.PackedAddress(), false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     testAmount,
		Randomness: testAnchorNorm,
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
