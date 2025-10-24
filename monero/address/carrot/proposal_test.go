package carrot

import (
	"math"
	unsafeRandom "math/rand/v2"
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

func TestPaymentProposalV1_CoinbaseOutput(t *testing.T) {
	expectedEnote := CoinbaseEnoteV1{
		OneTimeAddress:  crypto.PublicKeyBytes(types.MustHashFromString("a3d1d782671a3622bf393fe8116c8df95e9e12776e2970ab1934645f40748343")),
		Amount:          monero.TailEmissionReward,
		EncryptedAnchor: [monero.JanusAnchorSize]byte(hex.MustDecodeString("fa1d74f7a4891086a900e72776c521ed")),
		ViewTag:         [monero.CarrotViewTagSize]byte(hex.MustDecodeString("74b582")),
		EphemeralPubKey: crypto.X25519PublicKey(types.MustHashFromString("1b10ce3755cc36e2fda4031a56b589f29e2e727ab0e222be05f30f84c5c1b747")),
		BlockIndex:      123456,
	}

	addr := address.PackedAddress{
		crypto.PublicKeyBytes(types.MustHashFromString("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")),
		crypto.PublicKeyBytes(types.MustHashFromString("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")),
	}
	proposal := &PaymentProposalV1{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(&addr, false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55")),
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
	addr := address.PackedAddress{
		crypto.PublicKeyBytes(types.MustHashFromString("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")),
		crypto.PublicKeyBytes(types.MustHashFromString("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")),
	}
	prop := &PaymentProposalV1{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(&addr, false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55")),
	}

	b.Run("TorsionChecked", func(b *testing.B) {
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
	})

	b.Run("TorsionUnchecked", func(b *testing.B) {
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
	})

}

func BenchmarkPaymentProposalV1_CoinbaseOutput(b *testing.B) {
	addr := address.PackedAddress{
		crypto.PublicKeyBytes(types.MustHashFromString("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")),
		crypto.PublicKeyBytes(types.MustHashFromString("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")),
	}
	prop := &PaymentProposalV1{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(&addr, false),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55")),
	}

	b.Run("TorsionChecked", func(b *testing.B) {
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
	})

	b.Run("TorsionUnchecked", func(b *testing.B) {
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
	})
}

func BenchmarkPaymentProposalV1_Output(b *testing.B) {
	addr := address.PackedAddress{
		crypto.PublicKeyBytes(types.MustHashFromString("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")),
		crypto.PublicKeyBytes(types.MustHashFromString("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")),
	}

	firstKeyImage := crypto.PublicKeyBytes(types.MustHashFromString("a3d1d782671a3622bf393fe8116c8df95e9e12776e2970ab1934645f40748343"))
	prop := &PaymentProposalV1{
		Destination: DestinationV1{
			Address:   address.NewPackedAddressWithSubaddress(&addr, true),
			PaymentId: [monero.PaymentIdSize]byte{},
		},
		Amount:     monero.TailEmissionReward,
		Randomness: [monero.JanusAnchorSize]byte(hex.MustDecodeString("caee1381775487a0982557f0d2680b55")),
	}

	b.Run("TorsionChecked", func(b *testing.B) {
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
	})

	b.Run("TorsionUnchecked", func(b *testing.B) {
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
	})
}
