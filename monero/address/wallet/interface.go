package wallet

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
)

type SpendWalletInterface[T curve25519.PointOperations] interface {
	ViewWalletInterface[T]

	// Opening Used along a spend private key to calculate index private extension openings
	Opening(index address.SubaddressIndex) (keyG, keyT *curve25519.Scalar, spendPub *curve25519.PublicKey[T])
}

type CarrotWalletInterface[T curve25519.PointOperations] interface {
	SpendWalletInterface[T]

	ViewWallet() *CarrotViewWallet[T]
}

type SpendWalletLegacyInterface[T curve25519.PointOperations] interface {
	SpendWalletInterface[T]
	ViewWalletLegacyInterface[T]

	ViewWallet() *ViewWallet[T]
}

type ViewWalletInterface[T curve25519.PointOperations] interface {
	Get(ix address.SubaddressIndex) *address.Address
	Track(ix address.SubaddressIndex) error
	HasSpend(spendPub curve25519.PublicKeyBytes) (address.SubaddressIndex, bool)

	MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, commitments []ringct.Amount, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
	MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
}

type LegacyScan struct {
	ExtensionG curve25519.Scalar
	// ExtensionT Always zero/one?
	ExtensionT curve25519.Scalar
	SpendPub   curve25519.PublicKeyBytes

	PaymentId [monero.PaymentIdSize]byte
}

type ViewWalletLegacyInterface[T curve25519.PointOperations] interface {
	ViewWalletInterface[T]

	// Match Only available in non-Carrot legacy implementation
	Match(outputs transaction.Outputs, txPubs ...curve25519.PublicKeyBytes) (index int, scan *LegacyScan, addressIndex address.SubaddressIndex)
}
