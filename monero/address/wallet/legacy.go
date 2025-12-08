package wallet

import (
	"errors"
	"fmt"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/cryptonote"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
)

type ViewWallet[T curve25519.PointOperations] struct {
	primaryAddress  *address.Address
	accountSpendPub curve25519.PublicKey[T]
	viewKeyScalar   curve25519.Scalar
	viewKey         curve25519.PrivateKeyBytes
	// spendMap used to lookup spend keys to subaddress index
	spendMap map[curve25519.PublicKeyBytes]address.SubaddressIndex
}

// NewViewWallet Creates a new ViewWallet with the specified account and index depth. The main address is always tracked
func NewViewWallet[T curve25519.PointOperations](primaryAddress *address.Address, viewKey *curve25519.Scalar, accountDepth, indexDepth int) (*ViewWallet[T], error) {
	if primaryAddress == nil || primaryAddress.IsSubaddress() || !primaryAddress.Valid() {
		return nil, errors.New("address must be a main valid one")
	}

	if viewKey == nil {
		return nil, errors.New("view key must be valid")
	}

	if new(curve25519.PublicKey[T]).ScalarBaseMult(viewKey).AsBytes() != *primaryAddress.ViewPublicKey() {
		return nil, errors.New("view key public must be equal to primary address pub key")
	}

	var accountSpendPub curve25519.PublicKey[T]
	if _, err := accountSpendPub.SetBytes(primaryAddress.SpendPublicKey()[:]); err != nil {
		return nil, fmt.Errorf("account spend pub key must be valid: %w", err)
	}

	w := &ViewWallet[T]{
		accountSpendPub: accountSpendPub,
		primaryAddress:  primaryAddress,
		viewKeyScalar:   *viewKey,
		viewKey:         curve25519.PrivateKeyBytes(viewKey.Bytes()),
		spendMap:        make(map[curve25519.PublicKeyBytes]address.SubaddressIndex),
	}
	w.spendMap[primaryAddress.SpendPub] = address.ZeroSubaddressIndex

	if accountDepth != 0 || indexDepth != 0 {
		for account := range accountDepth + 1 {
			for index := range indexDepth + 1 {
				if err := w.Track(address.SubaddressIndex{Account: uint32(account), Offset: uint32(index)}); err != nil {
					return nil, err
				}
			}
		}
	}

	return w, nil
}

// Track Adds the subaddress index to track map
func (w *ViewWallet[T]) Track(ix address.SubaddressIndex) error {
	if ix != address.ZeroSubaddressIndex {
		w.spendMap[cryptonote.GetSubaddressSpendPub(&w.accountSpendPub, w.viewKey, ix)] = ix
	}
	return nil
}

// Match Matches a list of outputs from a transaction
func (w *ViewWallet[T]) Match(outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes) (index int, scan *LegacyScan, addressIndex address.SubaddressIndex) {
	var sharedDataPub, ephemeralPub curve25519.PublicKey[T]
	var err error
	var extensionG curve25519.Scalar
	var derivation curve25519.PublicKey[T]
	var publicKey curve25519.PublicKey[T]
	for _, pub := range txPubs {
		if _, err := publicKey.SetBytes(pub[:]); err != nil {
			continue
		}
		address.GetDerivation(&derivation, &publicKey, &w.viewKeyScalar)
		//TODO: optimize order?
		for _, out := range outputs {
			if out.Type != transaction.TxOutToKey && out.Type != transaction.TxOutToTaggedKey {
				continue
			}

			_, viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndex(&extensionG, derivation.AsBytes(), out.Index)
			if out.Type == transaction.TxOutToTaggedKey && viewTag != out.ViewTag.Slice()[0] {
				continue
			}

			sharedDataPub.ScalarBaseMult(&extensionG)

			_, err = ephemeralPub.P().SetBytes(out.EphemeralPublicKey[:])
			if err != nil {
				return -1, nil, address.ZeroSubaddressIndex
			}

			D := ephemeralPub.Subtract(&ephemeralPub, &sharedDataPub)

			scan = &LegacyScan{
				ExtensionG: extensionG,
				// zero
				ExtensionT: *new(curve25519.Scalar),
				SpendPub:   D.AsBytes(),
				//TODO: payment id
			}

			if len(commitments) > int(out.Index) {
				c := commitments[int(out.Index)]
				lc := c.Decode(curve25519.PrivateKeyBytes(extensionG.Bytes()), c.Mask == curve25519.ZeroPrivateKeyBytes)
				if ringct.CalculateCommitment(new(curve25519.PublicKey[T]), lc).AsBytes() != c.Commitment {
					// cannot match!
					continue
				}
				scan.Amount = lc.Amount
				copy(scan.AmountBlindingFactor[:], lc.Mask.Bytes())
			} else if out.Amount > 0 {
				// probably coinbase or old
				scan.Amount = out.Amount
				copy(scan.AmountBlindingFactor[:], ringct.CoinbaseAmountBlindingFactor.Bytes())
			}

			if ix, ok := w.HasSpend(scan.SpendPub); ok {
				return int(out.Index), scan, ix
			} else if len(commitments) > int(out.Index) {
				// we checked commitment, this is probably it - shared data is fine, we just don't know the specific index
				// return unknown index.
				// we cannot do this for transparent outputs (coinbase, or pre-RingCT)
				return int(out.Index), scan, address.UnknownSubaddressIndex
			}
		}
	}

	return -1, nil, address.ZeroSubaddressIndex
}

//nolint:dupl
func (w *ViewWallet[T]) MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	inputContext := carrot.MakeCoinbaseInputContext(blockIndex)
	scan = &carrot.ScanV1{}
	for _, pub := range txPubs {

		//TODO: optimize order from pubs?
		for _, out := range outputs {
			if out.Type != transaction.TxOutToCarrotV1 {
				continue
			}
			enote := carrot.CoinbaseEnoteV1{
				OneTimeAddress:  out.EphemeralPublicKey,
				Amount:          out.Amount,
				EncryptedAnchor: out.EncryptedJanusAnchor,
				ViewTag:         out.ViewTag,
				EphemeralPubKey: curve25519.MontgomeryPoint(pub),
				BlockIndex:      blockIndex,
			}

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(&w.viewKeyScalar, &enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				} else {
					return int(out.Index), scan, address.UnknownSubaddressIndex
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *ViewWallet[T]) MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	inputContext := carrot.MakeInputContext(firstKeyImage)
	scan = &carrot.ScanV1{}

	if len(commitments) != len(outputs) {
		return -1, nil, address.ZeroSubaddressIndex
	}

	for _, pub := range txPubs {

		//TODO: optimize order from pubs?
		for i, out := range outputs {
			if out.Type != transaction.TxOutToCarrotV1 {
				continue
			}
			enote := carrot.EnoteV1{
				OneTimeAddress:   out.EphemeralPublicKey,
				EncryptedAnchor:  out.EncryptedJanusAnchor.Value(),
				EncryptedAmount:  [monero.EncryptedAmountSize]byte(commitments[i].Amount[:]),
				AmountCommitment: commitments[i].Commitment,
				ViewTag:          out.ViewTag.Value(),
				EphemeralPubKey:  curve25519.MontgomeryPoint(pub),
				FirstKeyImage:    firstKeyImage,
			}

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(&w.viewKeyScalar, &enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				} else {
					return int(out.Index), scan, address.UnknownSubaddressIndex
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *ViewWallet[T]) HasSpend(spendPub curve25519.PublicKeyBytes) (address.SubaddressIndex, bool) {
	ix, ok := w.spendMap[spendPub]
	return ix, ok
}

func (w *ViewWallet[T]) GetFromSpend(spendPub *curve25519.PublicKey[T]) *address.Address {
	if w.accountSpendPub.Equal(spendPub) == 1 {
		return w.primaryAddress
	}

	var C curve25519.PublicKey[T]
	// view pub
	C.ScalarMult(&w.viewKeyScalar, spendPub)

	switch w.primaryAddress.BaseNetwork() {
	case monero.MainNetwork:
		return address.FromRawAddress(monero.SubAddressMainNetwork, spendPub.AsBytes(), C.AsBytes())
	case monero.TestNetwork:
		return address.FromRawAddress(monero.SubAddressTestNetwork, spendPub.AsBytes(), C.AsBytes())
	case monero.StageNetwork:
		return address.FromRawAddress(monero.SubAddressStageNetwork, spendPub.AsBytes(), C.AsBytes())
	default:
		return nil
	}
}

func (w *ViewWallet[T]) Get(index address.SubaddressIndex) *address.Address {
	if index.IsZero() {
		return w.primaryAddress
	}

	var D, C curve25519.PublicKey[T]
	cryptonote.GetSubaddressDC(&D, &C, &w.accountSpendPub, &w.viewKeyScalar, w.viewKey, index)

	switch w.primaryAddress.BaseNetwork() {
	case monero.MainNetwork:
		return address.FromRawAddress(monero.SubAddressMainNetwork, D.AsBytes(), C.AsBytes())
	case monero.TestNetwork:
		return address.FromRawAddress(monero.SubAddressTestNetwork, D.AsBytes(), C.AsBytes())
	case monero.StageNetwork:
		return address.FromRawAddress(monero.SubAddressStageNetwork, D.AsBytes(), C.AsBytes())
	default:
		return nil
	}
}

func (w *ViewWallet[T]) ViewKey() *curve25519.Scalar {
	return &w.viewKeyScalar
}
