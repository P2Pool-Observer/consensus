package wallet

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
)

type ViewWalletInterface[T curve25519.PointOperations] interface {
	Get(ix address.SubaddressIndex) *address.Address
	Track(ix address.SubaddressIndex) error
	HasSpend(spendPub curve25519.PublicKeyBytes) (address.SubaddressIndex, bool)

	// Opening Used along a spend private key to calculate index private extension openings
	Opening(index address.SubaddressIndex, spendKey *curve25519.Scalar) (keyG, keyT *curve25519.Scalar, spendPub *curve25519.PublicKey[T])

	MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, commitments []ringct.Amount, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
	MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
}

type ViewWalletLegacyInterface[T curve25519.PointOperations] interface {
	ViewWalletInterface[T]

	// Match Only available in non-Carrot legacy implementation
	Match(outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, txPub curve25519.PublicKeyBytes, sharedData *curve25519.Scalar, addressIndex address.SubaddressIndex)
}

func TrySearchForOpeningForSubaddress[T curve25519.PointOperations, ViewWallet ViewWalletInterface[T]](vw ViewWallet, spendPub *curve25519.PublicKey[T], spendKey *curve25519.Scalar) (keyG, keyT *curve25519.Scalar, ok bool) {
	index, ok := vw.HasSpend(spendPub.AsBytes())
	if !ok {
		return nil, nil, false
	}
	var recomputedSpendPub *curve25519.PublicKey[T]
	keyG, keyT, recomputedSpendPub = vw.Opening(index, spendKey)

	if recomputedSpendPub == nil || spendPub.Equal(recomputedSpendPub) == 0 {
		return nil, nil, false
	}

	return keyG, keyT, true
}

func TrySearchForOpeningForOneTimeAddress[T curve25519.PointOperations, ViewWallet ViewWalletInterface[T]](vw ViewWallet, spendPub *curve25519.PublicKey[T], spendKey *curve25519.Scalar, senderExtensionG, senderExtensionT *curve25519.Scalar) (x, y *curve25519.Scalar, ok bool) {
	// k^{j,g}_addr, k^{j,t}_addr
	keyG, keyT, ok := TrySearchForOpeningForSubaddress(vw, spendPub, spendKey)
	if !ok {
		return nil, nil, false
	}

	// x = k^{j,g}_addr + k^g_o
	x = new(curve25519.Scalar).Add(keyG, senderExtensionG)

	// y = k^{j,t}_addr + k^t_o
	y = new(curve25519.Scalar).Add(keyT, senderExtensionT)

	return x, y, true
}

func CanOpenOneTimeAddress[T curve25519.PointOperations, ViewWallet ViewWalletInterface[T]](vw ViewWallet, spendPub *curve25519.PublicKey[T], spendKey *curve25519.Scalar, senderExtensionG, senderExtensionT *curve25519.Scalar, oneTimeAddress *curve25519.PublicKey[T]) bool {
	senderExtensionPub := new(curve25519.PublicKey[T]).DoubleScalarBaseMultPrecomputed(senderExtensionT, crypto.GeneratorT, senderExtensionG)

	recomputedOneTimeAddress := new(curve25519.PublicKey[T]).Add(spendPub, senderExtensionPub)

	if oneTimeAddress.Equal(recomputedOneTimeAddress) == 0 {
		return false
	}

	x, y, ok := TrySearchForOpeningForOneTimeAddress(vw, spendPub, spendKey, senderExtensionG, senderExtensionT)
	if !ok {
		return false
	}

	// O' = x G + y T
	recomputedOneTimeAddress = new(curve25519.PublicKey[T]).DoubleScalarBaseMultPrecomputed(y, crypto.GeneratorT, x)

	// O' ?= O
	return oneTimeAddress.Equal(recomputedOneTimeAddress) == 1
}
