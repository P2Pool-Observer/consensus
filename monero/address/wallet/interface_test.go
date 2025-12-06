package wallet

import (
	"crypto/rand"
	"fmt"
	"testing"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/cryptonote"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func testScanCoinbase[T curve25519.PointOperations](t *testing.T, wallet SpendWalletInterface[T], ix address.SubaddressIndex) {
	addr := wallet.Get(ix)
	if addr == nil {
		t.Fatal("got nil address")
	}

	t.Run(fmt.Sprintf("Coinbase/#%d,%d", ix.Account, ix.Offset), func(t *testing.T) {
		const amount = monero.TailEmissionReward

		if lw, ok := wallet.(ViewWalletLegacyInterface[T]); ok {
			// test legacy
			t.Run("Legacy", func(t *testing.T) {

				txKey := curve25519.RandomScalar(new(curve25519.Scalar), rand.Reader)

				txPub := new(curve25519.PublicKey[T]).ScalarBaseMult(txKey)

				var addrI address.Interface
				if addr.IsSubaddress() {
					if vw, ok := wallet.(SpendWalletLegacyInterface[T]); ok {
						addrI = cryptonote.GetSubaddressFakeAddress(addr, vw.ViewWallet().ViewKey())
					} else {
						t.Skip("not supported")
					}
				} else {
					addrI = addr
				}

				out, _, _ := address.CalculateTransactionOutput[T](addrI, txKey, 0, amount)
				out.Amount = 0

				i, scan, subaddressIndex := lw.Match(transaction.Outputs{out}, txPub.AsBytes())
				if i != 0 {
					t.Fatalf("got index %d, want 0", i)
				}
				if subaddressIndex != ix {
					t.Fatalf("got subaddress index %+v, want %+v", subaddressIndex, ix)
				}

				// check spendability
				if err := CanOpenOneTimeAddress(wallet, curve25519.To[T](scan.SpendPub.Point()), &scan.ExtensionG, &scan.ExtensionT, curve25519.To[T](out.EphemeralPublicKey.Point())); err != nil {
					t.Fatalf("Spend Opening: cannot spend: %s", err)
				} else {
					t.Log("Spend Opening: OK")
				}
			})
		}

		t.Run("Carrot", func(t *testing.T) {
			if addr.IsSubaddress() {
				t.Skip("not supported")
			}

			proposal := carrot.PaymentProposalV1[T]{
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
				Amount:               amount,
				EphemeralPublicKey:   enote.OneTimeAddress,
				EncryptedJanusAnchor: enote.EncryptedAnchor,
				ViewTag:              enote.ViewTag,
			}

			i, scan, subaddressIndex := wallet.MatchCarrotCoinbase(blockIndex, transaction.Outputs{out}, curve25519.PublicKeyBytes(enote.EphemeralPubKey))
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
			if scan.Amount != proposal.Amount {
				t.Fatalf("got amount %d, want %d", scan.Amount, proposal.Amount)
			}
			if subaddressIndex != ix {
				t.Fatalf("got subaddress index %+v, want %+v", subaddressIndex, ix)
			}

			// check spendability
			if err := CanOpenOneTimeAddress(wallet, curve25519.To[T](scan.SpendPub.Point()), &scan.ExtensionG, &scan.ExtensionT, curve25519.To[T](out.EphemeralPublicKey.Point())); err != nil {
				t.Fatalf("Spend Opening: cannot spend: %s", err)
			} else {
				t.Log("Spend Opening: OK")
			}

			if cw, ok := wallet.(*CarrotSpendWallet[T]); ok {
				// check PQ turnstile
				var migrationTxSignableHash types.Hash
				_, _ = rand.Reader.Read(migrationTxSignableHash[:])

				sig := carrot.CreateSignatureT[T](migrationTxSignableHash, cw.ProveSpendKey(), rand.Reader)

				var senderReceiverSecret types.Hash

				{
					senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(cw.ViewWallet().ViewIncomingKey(), &enote.EphemeralPubKey)

					inputContext := carrot.MakeCoinbaseInputContext(blockIndex)

					senderReceiverSecret = carrot.MakeSenderReceiverSecret(&blake2b.Digest{}, senderReceiverUnctx, enote.EphemeralPubKey, inputContext[:])
				}

				pqt := carrot.PQTurnstile[T]{
					FetchOutput: func(id types.Hash, outputIndex int) (pub curve25519.PublicKeyBytes, commitment curve25519.PublicKeyBytes, err error) {
						return enote.OneTimeAddress, ringct.CalculateCommitmentCoinbase(new(curve25519.PublicKey[T]), enote.Amount).AsBytes(), nil
					},
					IsKeyImageSpent: func(ki curve25519.PublicKeyBytes) bool {
						return false
					},
				}

				if err := pqt.VerifyCoinbase(
					types.ZeroHash, 0,
					cw.PartialSpendPub(),
					cw.GenerateImagePreimageSecret(),
					senderReceiverSecret,
					proposal.Amount,
					migrationTxSignableHash,
					sig,
				); err != nil {
					t.Fatalf("PQ Turnstile: cannot verify: %s", err)
				} else {
					t.Log("PQ Turnstile: OK")
				}
			}
		})
	})
}

func testScanPayment[T curve25519.PointOperations](t *testing.T, wallet SpendWalletInterface[T], ix address.SubaddressIndex) {
	addr := wallet.Get(ix)
	if addr == nil {
		t.Fatal("got nil address")
	}

	t.Run(fmt.Sprintf("Payment/#%d,%d", ix.Account, ix.Offset), func(t *testing.T) {
		const amount = monero.TailEmissionReward

		if lw, ok := wallet.(SpendWalletLegacyInterface[T]); ok {
			// test legacy
			t.Run("Legacy", func(t *testing.T) {

				txKey := curve25519.RandomScalar(new(curve25519.Scalar), rand.Reader)

				txPub := new(curve25519.PublicKey[T]).ScalarBaseMult(txKey)

				out, additionalPub, encryptedAmount := address.CalculateTransactionOutput[T](addr, txKey, 0, amount)
				out.Amount = 0

				if additionalPub == nil {
					additionalPub = new(curve25519.PublicKey[T]).ScalarBaseMult(txKey)
				}

				i, scan, subaddressIndex := lw.Match(transaction.Outputs{out}, txPub.AsBytes(), additionalPub.AsBytes())
				if i != 0 {
					t.Fatalf("got index %d, want 0", i)
				}

				if subaddressIndex != ix {
					t.Fatalf("got subaddress index %+v, want %+v", subaddressIndex, ix)
				}

				// check spendability
				if err := CanOpenOneTimeAddress(wallet, curve25519.To[T](scan.SpendPub.Point()), &scan.ExtensionG, &scan.ExtensionT, curve25519.To[T](out.EphemeralPublicKey.Point())); err != nil {
					t.Fatalf("Spend Opening: cannot spend: %s", err)
				} else {
					t.Log("Spend Opening: OK")
				}

				decryptedAmount := ringct.DecryptOutputAmount(curve25519.PrivateKeyBytes(scan.ExtensionG.Bytes()), encryptedAmount)
				if decryptedAmount != amount {
					t.Fatalf("got amount %d, want %d", decryptedAmount, amount)
				}
			})
		}

		t.Run("Carrot", func(t *testing.T) {
			proposal := carrot.PaymentProposalV1[T]{
				Destination: carrot.DestinationV1{
					Address: address.NewPackedAddressWithSubaddressFromBytes(addr.SpendPub, addr.ViewPub, addr.IsSubaddress()),
				},
				Amount: amount,
			}
			_, _ = rand.Read(proposal.Randomness[:])

			var firstKeyImage curve25519.PublicKeyBytes
			_, _ = rand.Read(firstKeyImage[:])
			var enote carrot.RCTEnoteProposal

			err := proposal.Output(&enote, firstKeyImage)
			if err != nil {
				t.Fatal(err)
			}

			out := transaction.Output{
				Type:                 transaction.TxOutToCarrotV1,
				Amount:               amount,
				EphemeralPublicKey:   enote.Enote.OneTimeAddress,
				EncryptedJanusAnchor: types.MakeFixed(enote.Enote.EncryptedAnchor),
				ViewTag:              types.MakeFixed(enote.Enote.ViewTag),
			}
			i, scan, subaddressIndex := wallet.MatchCarrot(firstKeyImage,
				[]ringct.Amount{
					{
						Encrypted:  enote.Enote.EncryptedAmount,
						Commitment: enote.Enote.AmountCommitment,
					},
				},
				transaction.Outputs{out}, curve25519.PublicKeyBytes(enote.Enote.EphemeralPubKey))
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

			// check spendability
			if err := CanOpenOneTimeAddress(wallet, curve25519.To[T](scan.SpendPub.Point()), &scan.ExtensionG, &scan.ExtensionT, curve25519.To[T](out.EphemeralPublicKey.Point())); err != nil {
				t.Fatalf("Spend Opening: cannot spend: %s", err)
			} else {
				t.Log("Spend Opening: OK")
			}

			if cw, ok := wallet.(*CarrotSpendWallet[T]); ok {
				// check PQ turnstile
				var migrationTxSignableHash types.Hash
				_, _ = rand.Reader.Read(migrationTxSignableHash[:])

				sig := carrot.CreateSignatureT[T](migrationTxSignableHash, cw.ProveSpendKey(), rand.Reader)

				var senderReceiverSecret types.Hash

				{
					senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(cw.ViewWallet().ViewIncomingKey(), &enote.Enote.EphemeralPubKey)

					inputContext := carrot.MakeInputContext(firstKeyImage)

					senderReceiverSecret = carrot.MakeSenderReceiverSecret(&blake2b.Digest{}, senderReceiverUnctx, enote.Enote.EphemeralPubKey, inputContext[:])
				}

				addressIndexPreimage1 := carrot.MakeAddressIndexPreimage1(&blake2b.Digest{}, cw.ViewWallet().GenerateAddressSecret(), ix)
				addressIndexPreimage2 := carrot.MakeAddressIndexPreimage2(&blake2b.Digest{}, addressIndexPreimage1, cw.ViewWallet().AccountSpendPub().AsBytes(), cw.ViewWallet().AccountViewPub().AsBytes(), ix)

				pqt := carrot.PQTurnstile[T]{
					FetchOutput: func(id types.Hash, outputIndex int) (pub curve25519.PublicKeyBytes, commitment curve25519.PublicKeyBytes, err error) {
						return enote.Enote.OneTimeAddress, enote.Enote.AmountCommitment, nil
					},
					IsKeyImageSpent: func(ki curve25519.PublicKeyBytes) bool {
						return false
					},
				}

				if err := pqt.Verify(
					types.ZeroHash, 0,
					cw.PartialSpendPub(),
					cw.GenerateImagePreimageSecret(),
					addr.IsSubaddress(),
					addressIndexPreimage2,
					senderReceiverSecret,
					proposal.Amount,
					carrot.EnoteTypePayment,
					migrationTxSignableHash,
					sig,
				); err != nil {
					t.Fatalf("PQ Turnstile: cannot verify: %s", err)
				} else {
					t.Log("PQ Turnstile: OK")
				}
			}
		})
	})
}
