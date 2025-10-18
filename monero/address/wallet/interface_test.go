package wallet

import (
	"crypto/rand"
	"fmt"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
)

func testScanCoinbase(t *testing.T, wallet ViewWalletInterface, ix address.SubaddressIndex) {
	addr := wallet.Get(ix)
	if addr == nil {
		t.Fatal("got nil address")
	}

	t.Run(fmt.Sprintf("Coinbase/#%d,%d", ix.Account, ix.Offset), func(t *testing.T) {
		const amount = monero.TailEmissionReward

		if lw, ok := wallet.(ViewWalletLegacyInterface); ok {
			// test legacy
			t.Run("Legacy", func(t *testing.T) {

				txKey := crypto.PrivateKeyFromScalar(crypto.RandomScalar())

				txPub := txKey.PublicKey().AsBytes()

				var addrI address.Interface
				if addr.IsSubaddress() {
					if vw, ok := wallet.(*ViewWallet); ok {
						addrI = address.GetSubaddressFakeAddress(addr, vw.ViewKey())
					} else {
						t.Skip("not supported")
					}
				} else {
					addrI = addr
				}

				out, _, _ := address.CalculateTransactionOutput(addrI, txKey, 0, amount)
				out.Reward = 0

				i, pub, _, subaddressIndex := lw.Match(transaction.Outputs{out}, txPub.AsBytes())
				if i != 0 {
					t.Fatalf("got index %d, want 0", i)
				}
				if pub.AsBytes() != txPub.AsBytes() {
					t.Fatalf("got pub %s, want %s", pub.String(), txPub.String())
				}
				if subaddressIndex != ix {
					t.Fatalf("got subaddress index %+v, want %+v", subaddressIndex, ix)
				}
			})
		}

		t.Run("Carrot", func(t *testing.T) {
			if addr.IsSubaddress() {
				t.Skip("not supported")
			}

			proposal := carrot.PaymentProposalV1{
				Destination: carrot.DestinationV1{
					Address: address.NewPackedAddressWithSubaddressFromBytes(addr.SpendPub, addr.ViewPub, addr.IsSubaddress()),
				},
				Amount: amount,
			}
			_, _ = rand.Read(proposal.Randomness[:])

			var enote carrot.CoinbaseEnoteV1
			const blockIndex = 123456
			err := proposal.CoinbaseOutput(&enote, blockIndex)
			if err != nil {
				t.Fatal(err)
			}

			out := transaction.Output{
				Type:                 transaction.TxOutToCarrotV1,
				Reward:               amount,
				EphemeralPublicKey:   enote.OneTimeAddress,
				EncryptedJanusAnchor: enote.EncryptedAnchor,
				ViewTag:              enote.ViewTag,
			}

			i, scan, subaddressIndex := wallet.MatchCarrotCoinbase(blockIndex, transaction.Outputs{out}, crypto.PublicKeyBytes(enote.EphemeralPubKey))
			if i != 0 {
				t.Fatalf("got index %d, want 0", i)
			}
			if scan.SpendPub != addr.SpendPub {
				t.Fatalf("got spend pub %s, want %s", scan.SpendPub.String(), addr.SpendPub.String())
			}
			if scan.Randomness != proposal.Randomness {
				t.Fatalf("got randomnness %x, want %x", scan.Randomness[:], proposal.Randomness[:])
			}
			if scan.PaymentId != proposal.Destination.PaymentId {
				t.Fatalf("got payment id %x, want %x", scan.PaymentId[:], proposal.Destination.PaymentId[:])
			}
			if subaddressIndex != ix {
				t.Fatalf("got subaddress index %+v, want %+v", subaddressIndex, ix)
			}
		})
	})
}

func testScanPayment(t *testing.T, wallet ViewWalletInterface, ix address.SubaddressIndex) {
	addr := wallet.Get(ix)
	if addr == nil {
		t.Fatal("got nil address")
	}

	t.Run(fmt.Sprintf("Payment/#%d,%d", ix.Account, ix.Offset), func(t *testing.T) {
		const amount = monero.TailEmissionReward

		if lw, ok := wallet.(ViewWalletLegacyInterface); ok {
			// test legacy
			t.Run("Legacy", func(t *testing.T) {

				txKey := crypto.PrivateKeyFromScalar(crypto.RandomScalar())

				out, additionalPub, encryptedAmount := address.CalculateTransactionOutput(addr, txKey, 0, amount)
				out.Reward = 0

				if additionalPub == nil {
					additionalPub = txKey.PublicKey()
				}

				i, pub, sharedData, subaddressIndex := lw.Match(transaction.Outputs{out}, txKey.PublicKey().AsBytes(), additionalPub.AsBytes())
				if i != 0 {
					t.Fatalf("got index %d, want 0", i)
				}
				if pub.AsBytes() != additionalPub.AsBytes() {
					t.Fatalf("got pub %s, want %s", pub.String(), additionalPub.String())
				}
				if subaddressIndex != ix {
					t.Fatalf("got subaddress index %+v, want %+v", subaddressIndex, ix)
				}

				decryptedAmount := crypto.DecryptOutputAmount(sharedData, encryptedAmount)
				if decryptedAmount != amount {
					t.Fatalf("got amount %d, want %d", decryptedAmount, amount)
				}
			})
		}

		t.Run("Carrot", func(t *testing.T) {
			proposal := carrot.PaymentProposalV1{
				Destination: carrot.DestinationV1{
					Address: address.NewPackedAddressWithSubaddressFromBytes(addr.SpendPub, addr.ViewPub, addr.IsSubaddress()),
				},
				Amount: amount,
			}
			_, _ = rand.Read(proposal.Randomness[:])

			var firstKeyImage crypto.PublicKeyBytes
			_, _ = rand.Read(firstKeyImage[:])
			var enote carrot.RCTEnoteProposal

			err := proposal.Output(&enote, firstKeyImage)
			if err != nil {
				t.Fatal(err)
			}

			out := transaction.Output{
				Type:                 transaction.TxOutToCarrotV1,
				Reward:               amount,
				EphemeralPublicKey:   enote.Enote.OneTimeAddress,
				EncryptedJanusAnchor: enote.Enote.EncryptedAnchor,
				ViewTag:              enote.Enote.ViewTag,
			}
			i, scan, subaddressIndex := wallet.MatchCarrot(firstKeyImage,
				[]crypto.RCTAmount{
					{
						Encrypted:  enote.Enote.EncryptedAmount,
						Commitment: enote.Enote.AmountCommitment,
					},
				},
				transaction.Outputs{out}, crypto.PublicKeyBytes(enote.Enote.EphemeralPubKey))
			if i != 0 {
				t.Fatalf("got index %d, want 0", i)
			}
			if scan.SpendPub != addr.SpendPub {
				t.Fatalf("got spend pub %s, want %s", scan.SpendPub.String(), addr.SpendPub.String())
			}
			if scan.Randomness != proposal.Randomness {
				t.Fatalf("got randomnness %x, want %x", scan.Randomness[:], proposal.Randomness[:])
			}
			if scan.AmountBlindingFactor != enote.AmountBlindingFactor {
				t.Fatalf("got randomnness %x, want %x", scan.AmountBlindingFactor[:], enote.AmountBlindingFactor[:])
			}
			if scan.Amount != proposal.Amount {
				t.Fatalf("got amount %d, want %d", scan.Amount, proposal.Amount)
			}
			if scan.PaymentId != proposal.Destination.PaymentId {
				t.Fatalf("got payment id %x, want %x", scan.PaymentId[:], proposal.Destination.PaymentId[:])
			}
			if subaddressIndex != ix {
				t.Fatalf("got subaddress index %+v, want %+v", subaddressIndex, ix)
			}
		})
	})
}
