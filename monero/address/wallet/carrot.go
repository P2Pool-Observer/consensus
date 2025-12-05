package wallet

import (
	"errors"
	"fmt"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func NewCarrotViewWalletFromViewBalanceSecret[T curve25519.PointOperations](partialSpendPub *curve25519.PublicKey[T], viewBalanceSecret types.Hash, addressNetwork uint8, accountDepth, indexDepth int) (*CarrotViewWallet[T], error) {
	var hasher blake2b.Digest

	generateImagePreimageSecret := carrot.MakeGenerateImagePreimageSecret(&hasher, viewBalanceSecret)

	var generateImage, viewIncoming curve25519.Scalar
	carrot.MakeGenerateImageKey(&hasher, &generateImage, partialSpendPub.AsBytes(), generateImagePreimageSecret)
	generateAddressSecret := carrot.MakeGenerateAddressSecret(&hasher, viewBalanceSecret)

	carrot.MakeViewIncomingKey(&hasher, &viewIncoming, viewBalanceSecret)

	var spendPub, viewPub curve25519.PublicKey[T]
	carrot.MakeSpendPubFromPartialSpendPub(&spendPub, &generateImage, partialSpendPub)
	carrot.MakePrimaryAddressViewPub(&viewPub, &viewIncoming)

	return NewCarrotViewWallet[T](
		address.FromRawAddress(addressNetwork, spendPub.AsBytes(), viewPub.AsBytes()),
		&generateImage,
		&viewIncoming,
		generateAddressSecret,
		accountDepth,
		indexDepth,
	)
}

type CarrotViewWallet[T curve25519.PointOperations] struct {
	primaryAddress *address.Address
	// generateImageKeyScalar can be nil
	generateImageKeyScalar *curve25519.Scalar
	viewIncomingKeyScalar  curve25519.Scalar
	viewIncomingKey        curve25519.PrivateKeyBytes

	generateAddressSecret types.Hash

	// carrot public keys (minus K^0_v, which is shared with legacy K^0_v)
	accountSpendPub curve25519.PublicKey[T]
	accountViewPub  curve25519.PublicKey[T]

	// spendMap used to lookup spend keys to subaddress index
	spendMap map[curve25519.PublicKeyBytes]address.SubaddressIndex
}

// NewCarrotViewWallet Creates a new CarrotViewWallet with the specified account and index depth. The main address is always tracked
func NewCarrotViewWallet[T curve25519.PointOperations](primaryAddress *address.Address, generateImageKey, viewIncomingKey *curve25519.Scalar, generateAddressSecret types.Hash, accountDepth, indexDepth int) (*CarrotViewWallet[T], error) {
	if primaryAddress == nil || primaryAddress.IsSubaddress() || !primaryAddress.Valid() {
		return nil, errors.New("address must be a main valid one")
	}

	if viewIncomingKey == nil {
		return nil, errors.New("view incoming key must be valid")
	}

	if generateAddressSecret == types.ZeroHash {
		return nil, errors.New("generate address secret must be non-zero")
	}

	if new(curve25519.PublicKey[T]).ScalarBaseMult(viewIncomingKey).AsBytes() != *primaryAddress.ViewPublicKey() {
		return nil, errors.New("view incoming key public must be equal to primary address pub key")
	}

	var accountSpendPub, accountViewPub curve25519.PublicKey[T]
	if _, err := accountSpendPub.SetBytes(primaryAddress.SpendPublicKey()[:]); err != nil {
		return nil, fmt.Errorf("account spend pub key must be valid: %w", err)
	}
	carrot.MakeAccountViewPub(&accountViewPub, viewIncomingKey, &accountSpendPub)

	w := &CarrotViewWallet[T]{
		primaryAddress:         primaryAddress,
		generateImageKeyScalar: generateImageKey,
		accountViewPub:         accountViewPub,
		accountSpendPub:        accountSpendPub,
		viewIncomingKeyScalar:  *viewIncomingKey,
		viewIncomingKey:        curve25519.PrivateKeyBytes(viewIncomingKey.Bytes()),
		generateAddressSecret:  generateAddressSecret,
		spendMap:               make(map[curve25519.PublicKeyBytes]address.SubaddressIndex),
	}

	w.spendMap[accountSpendPub.AsBytes()] = address.ZeroSubaddressIndex

	var hasher blake2b.Digest

	if accountDepth != 0 || indexDepth != 0 {
		for account := range accountDepth + 1 {
			for index := range indexDepth + 1 {
				if err := w.track(&hasher, address.SubaddressIndex{Account: uint32(account), Offset: uint32(index)}); err != nil {
					return nil, err
				}
			}
		}
	}

	return w, nil
}

// Track Adds the subaddress index to track map
func (w *CarrotViewWallet[T]) Track(ix address.SubaddressIndex) error {
	var hasher blake2b.Digest
	return w.track(&hasher, ix)
}

func (w *CarrotViewWallet[T]) track(hasher *blake2b.Digest, ix address.SubaddressIndex) error {
	if ix == address.ZeroSubaddressIndex {
		return nil
	}

	w.spendMap[carrot.MakeDestinationSubaddressSpendPub(hasher, &w.accountSpendPub, &w.accountViewPub, w.generateAddressSecret, ix)] = ix
	return nil
}

//nolint:dupl
func (w *CarrotViewWallet[T]) MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	inputContext := carrot.MakeCoinbaseInputContext(blockIndex)
	scan = &carrot.ScanV1{}
	for _, pub := range txPubs {

		//TODO: optimize order from pubs?
		for _, out := range outputs {
			enote := carrot.CoinbaseEnoteV1{
				OneTimeAddress:  out.EphemeralPublicKey,
				Amount:          out.Amount,
				EncryptedAnchor: out.EncryptedJanusAnchor,
				ViewTag:         out.ViewTag,
				EphemeralPubKey: curve25519.MontgomeryPoint(pub),
				BlockIndex:      blockIndex,
			}

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(&w.viewIncomingKeyScalar, &enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *CarrotViewWallet[T]) MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, commitments []ringct.Amount, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
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

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(&w.viewIncomingKeyScalar, &enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *CarrotViewWallet[T]) HasSpend(spendPub curve25519.PublicKeyBytes) (address.SubaddressIndex, bool) {
	ix, ok := w.spendMap[spendPub]
	return ix, ok
}

func (w *CarrotViewWallet[T]) Get(index address.SubaddressIndex) *address.Address {
	if index.IsZero() {
		return w.primaryAddress
	}
	var hasher blake2b.Digest
	sa, err := carrot.MakeDestinationSubaddress(&hasher, &w.accountSpendPub, &w.accountViewPub, w.generateAddressSecret, index)
	if err != nil {
		return nil
	}

	switch w.primaryAddress.TypeNetwork {
	case monero.MainNetwork:
		return address.FromRawAddress(monero.SubAddressMainNetwork, *sa.Address.SpendPublicKey(), *sa.Address.ViewPublicKey())
	case monero.TestNetwork:
		return address.FromRawAddress(monero.SubAddressTestNetwork, *sa.Address.SpendPublicKey(), *sa.Address.ViewPublicKey())
	case monero.StageNetwork:
		return address.FromRawAddress(monero.SubAddressStageNetwork, *sa.Address.SpendPublicKey(), *sa.Address.ViewPublicKey())
	default:
		return nil
	}
}

func (w *CarrotViewWallet[T]) AccountSpendPub() *curve25519.PublicKey[T] {
	return &w.accountSpendPub
}

func (w *CarrotViewWallet[T]) AccountViewPub() *curve25519.PublicKey[T] {
	return &w.accountViewPub
}

func (w *CarrotViewWallet[T]) GenerateImageKey() *curve25519.Scalar {
	return w.generateImageKeyScalar
}

func (w *CarrotViewWallet[T]) GenerateAddressSecret() types.Hash {
	return w.generateAddressSecret
}

func (w *CarrotViewWallet[T]) ViewIncomingKey() *curve25519.Scalar {
	return &w.viewIncomingKeyScalar
}
