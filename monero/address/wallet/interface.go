package wallet

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
)

type ViewWalletInterface interface {
	Get(ix address.SubaddressIndex) *address.Address
	Track(ix address.SubaddressIndex) error
	HasSpend(spendPub crypto.PublicKeyBytes) (address.SubaddressIndex, bool)

	MatchCarrot(firstKeyImage crypto.PublicKeyBytes, commitments []crypto.RCTAmount, outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
	MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
}

type ViewWalletLegacyInterface interface {
	ViewWalletInterface

	// Match Only available in non-Carrot legacy implementation
	Match(outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, txPub crypto.PublicKeyBytes, sharedData crypto.PrivateKey, addressIndex address.SubaddressIndex)
}
