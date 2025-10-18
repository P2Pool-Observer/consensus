package wallet

import (
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

type ViewWallet struct {
	primaryAddress *address.Address
	viewKeyScalar  *crypto.PrivateKeyScalar
	viewKeyBytes   crypto.PrivateKeyBytes
	// spendMap used to lookup spend keys to subaddress index
	spendMap map[crypto.PublicKeyBytes]address.SubaddressIndex
}

func NewViewWalletFromSpendKey(spendKey crypto.PrivateKey, addressNetwork uint8, accountDepth, indexDepth int) (*ViewWallet, error) {
	viewKey := crypto.PrivateKeyFromScalar(crypto.ScalarDeriveLegacy(spendKey.AsSlice()))
	return NewViewWallet(address.FromRawAddress(addressNetwork, spendKey.PublicKey(), viewKey.PublicKey()), viewKey, accountDepth, indexDepth)
}

// NewViewWallet Creates a new ViewWallet with the specified account and index depth. The main address is always tracked
func NewViewWallet(primaryAddress *address.Address, viewKey crypto.PrivateKey, accountDepth, indexDepth int) (*ViewWallet, error) {
	if primaryAddress == nil || primaryAddress.IsSubaddress() || !primaryAddress.Valid() {
		return nil, errors.New("address must be a main valid one")
	}

	viewKeyScalar := viewKey.AsScalar()
	if viewKeyScalar == nil {
		return nil, errors.New("view key must be valid")
	}

	if viewKeyScalar.PublicKey().AsBytes() != *primaryAddress.ViewPublicKey() {
		return nil, errors.New("view key public must be equal to primary address pub key")
	}

	w := &ViewWallet{
		primaryAddress: primaryAddress,
		viewKeyScalar:  viewKeyScalar,
		viewKeyBytes:   viewKeyScalar.AsBytes(),
		spendMap:       make(map[crypto.PublicKeyBytes]address.SubaddressIndex),
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
func (w *ViewWallet) Track(ix address.SubaddressIndex) error {
	if ix != address.ZeroSubaddressIndex {
		w.spendMap[address.GetSubaddressSpendPub(w.primaryAddress, w.viewKeyBytes, ix)] = ix
	}
	return nil
}

// Match Matches a list of outputs from a transaction
func (w *ViewWallet) Match(outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, txPub crypto.PublicKeyBytes, sharedData crypto.PrivateKey, addressIndex address.SubaddressIndex) {
	var sharedDataPub, ephemeralPub edwards25519.Point
	var err error
	var sharedDataScalar edwards25519.Scalar
	for _, pub := range txPubs {
		derivation := w.viewKeyScalar.GetDerivationCofactor(&pub).AsBytes()
		//TODO: optimize order?
		for _, out := range outputs {
			viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(&sharedDataScalar, derivation, out.Index)
			if out.Type == transaction.TxOutToTaggedKey && viewTag != out.ViewTag.Slice()[0] {
				continue
			}

			sharedDataPub.UnsafeVarTimeScalarBaseMult(&sharedDataScalar)

			_, err = ephemeralPub.SetBytes(out.EphemeralPublicKey[:])
			if err != nil {
				return -1, crypto.PublicKeyBytes{}, nil, address.ZeroSubaddressIndex
			}

			D := ephemeralPub.Subtract(&ephemeralPub, &sharedDataPub)
			if ix, ok := w.HasSpend(crypto.PublicKeyBytes(D.Bytes())); ok {
				return int(out.Index), pub, crypto.PrivateKeyFromScalar(&sharedDataScalar), ix
			}
		}
	}

	return -1, crypto.PublicKeyBytes{}, nil, address.ZeroSubaddressIndex
}

func (w *ViewWallet) MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	inputContext := carrot.MakeCoinbaseInputContext(blockIndex)
	scan = &carrot.ScanV1{}
	for _, pub := range txPubs {

		//TODO: optimize order from pubs?
		for _, out := range outputs {
			enote := carrot.CoinbaseEnoteV1{
				OneTimeAddress:  out.EphemeralPublicKey,
				Amount:          out.Reward,
				EncryptedAnchor: out.EncryptedJanusAnchor.Value(),
				ViewTag:         out.ViewTag.Value(),
				EphemeralPubKey: crypto.X25519PublicKey(pub),
				BlockIndex:      blockIndex,
			}

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(w.viewKeyBytes, enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *ViewWallet) MatchCarrot(firstKeyImage crypto.PublicKeyBytes, commitments []crypto.RCTAmount, outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	inputContext := carrot.MakeInputContext(firstKeyImage)
	scan = &carrot.ScanV1{}

	if len(commitments) != len(outputs) {
		return -1, nil, address.ZeroSubaddressIndex
	}

	for _, pub := range txPubs {

		//TODO: optimize order from pubs?
		for i, out := range outputs {
			enote := carrot.EnoteV1{
				OneTimeAddress:   out.EphemeralPublicKey,
				EncryptedAnchor:  out.EncryptedJanusAnchor.Value(),
				EncryptedAmount:  commitments[i].Encrypted,
				AmountCommitment: commitments[i].Commitment,
				ViewTag:          out.ViewTag.Value(),
				EphemeralPubKey:  crypto.X25519PublicKey(pub),
				FirstKeyImage:    firstKeyImage,
			}

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(w.viewKeyBytes, enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *ViewWallet) HasSpend(spendPub crypto.PublicKeyBytes) (address.SubaddressIndex, bool) {
	ix, ok := w.spendMap[spendPub]
	return ix, ok
}

func (w *ViewWallet) Get(index address.SubaddressIndex) *address.Address {
	if index.IsZero() {
		return w.primaryAddress
	}
	return address.GetSubaddressNoAllocate(w.primaryAddress, w.viewKeyScalar, w.viewKeyBytes, index)
}

func (w *ViewWallet) ViewKey() crypto.PrivateKey {
	return w.viewKeyScalar
}
