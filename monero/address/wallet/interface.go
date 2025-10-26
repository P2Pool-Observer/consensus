package wallet

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
)

type ViewWalletInterface[T curve25519.PointOperations] interface {
	Get(ix address.SubaddressIndex) *address.Address
	Track(ix address.SubaddressIndex) error
	HasSpend(spendPub curve25519.PublicKeyBytes) (address.SubaddressIndex, bool)

	MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, commitments []crypto.RCTAmount, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
	MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
}

type ViewWalletLegacyInterface[T curve25519.PointOperations] interface {
	ViewWalletInterface[T]

	// Match Only available in non-Carrot legacy implementation
	Match(outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, txPub curve25519.PublicKeyBytes, sharedData *curve25519.Scalar, addressIndex address.SubaddressIndex)
}
