package wallet

import (
	"errors"

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

func NewViewWalletFromSpendKey[T curve25519.PointOperations](spendKey *curve25519.Scalar, addressNetwork uint8, accountDepth, indexDepth int) (*ViewWallet[T], error) {
	viewKey := crypto.ScalarDeriveLegacy(spendKey.Bytes())
	var spendPub, viewPub curve25519.PublicKey[T]
	spendPub.ScalarBaseMult(spendKey)
	viewPub.ScalarBaseMult(viewKey)
	return NewViewWallet[T](address.FromRawAddress(addressNetwork, spendPub.Bytes(), viewPub.Bytes()), viewKey, accountDepth, indexDepth)
}

// NewViewWallet Creates a new ViewWallet with the specified account and index depth. The main address is always tracked
func NewViewWallet[T curve25519.PointOperations](primaryAddress *address.Address, viewKey *curve25519.Scalar, accountDepth, indexDepth int) (*ViewWallet[T], error) {
	if primaryAddress == nil || primaryAddress.IsSubaddress() || !primaryAddress.Valid() {
		return nil, errors.New("address must be a main valid one")
	}

	if viewKey == nil {
		return nil, errors.New("view key must be valid")
	}

	if new(curve25519.PublicKey[T]).ScalarBaseMult(viewKey).Bytes() != *primaryAddress.ViewPublicKey() {
		return nil, errors.New("view key public must be equal to primary address pub key")
	}

	var accountSpendPub curve25519.PublicKey[T]
	if curve25519.DecodeCompressedPoint(&accountSpendPub, *primaryAddress.SpendPublicKey()) == nil {
		return nil, errors.New("account spend pub key must be valid")
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
func (w *ViewWallet[T]) Match(outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, txPub curve25519.PublicKeyBytes, sharedData *curve25519.Scalar, addressIndex address.SubaddressIndex) {
	var sharedDataPub, ephemeralPub curve25519.PublicKey[T]
	var err error
	var sharedDataScalar curve25519.Scalar
	var derivation curve25519.PublicKey[T]
	var publicKey curve25519.PublicKey[T]
	for _, pub := range txPubs {
		if curve25519.DecodeCompressedPoint(&publicKey, pub) == nil {
			continue
		}
		address.GetDerivation(&derivation, &publicKey, &w.viewKeyScalar)
		//TODO: optimize order?
		for _, out := range outputs {
			_, viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndex(&sharedDataScalar, derivation.Bytes(), out.Index)
			if out.Type == transaction.TxOutToTaggedKey && viewTag != out.ViewTag.Slice()[0] {
				continue
			}

			sharedDataPub.ScalarBaseMult(&sharedDataScalar)

			_, err = ephemeralPub.P().SetBytes(out.EphemeralPublicKey[:])
			if err != nil {
				return -1, curve25519.PublicKeyBytes{}, nil, address.ZeroSubaddressIndex
			}

			D := ephemeralPub.Subtract(&ephemeralPub, &sharedDataPub)
			if ix, ok := w.HasSpend(D.Bytes()); ok {
				return int(out.Index), pub, &sharedDataScalar, ix
			}
		}
	}

	return -1, curve25519.PublicKeyBytes{}, nil, address.ZeroSubaddressIndex
}

func (w *ViewWallet[T]) MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
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
				EphemeralPubKey: curve25519.MontgomeryPoint(pub),
				BlockIndex:      blockIndex,
			}

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(&w.viewKeyScalar, &enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *ViewWallet[T]) MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, commitments []ringct.Amount, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
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
				EphemeralPubKey:  curve25519.MontgomeryPoint(pub),
				FirstKeyImage:    firstKeyImage,
			}

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(&w.viewKeyScalar, &enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
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

func (w *ViewWallet[T]) Opening(index address.SubaddressIndex, spendKey *curve25519.Scalar) (keyG, keyT *curve25519.Scalar, spendPub *curve25519.PublicKey[T]) {
	// m = Hn(k_v || j_major || j_minor) if subaddress else 0
	subaddressExtension := cryptonote.SubaddressExtension(new(curve25519.Scalar), index, w.viewKey)

	keyG = new(curve25519.Scalar).Add(spendKey, subaddressExtension)
	keyT = new(curve25519.Scalar)

	// x G + y T
	spendPub = new(curve25519.PublicKey[T]).DoubleScalarBaseMultPrecomputed(keyT, crypto.GeneratorT, keyG)

	return keyG, keyT, spendPub
}

func (w *ViewWallet[T]) Get(index address.SubaddressIndex) *address.Address {
	if index.IsZero() {
		return w.primaryAddress
	}
	return cryptonote.GetSubaddressNoAllocate(w.primaryAddress.BaseNetwork(), &w.accountSpendPub, &w.viewKeyScalar, w.viewKey, index)
}

func (w *ViewWallet[T]) ViewKey() *curve25519.Scalar {
	return &w.viewKeyScalar
}
