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

	// MatchCarrot matches a Carrot non-coinbase from a list of outputs. Returns the absolute index of the matched output, scan data, and eligible address index if available
	// Slice outputs to continue scanning
	MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)

	// MatchCarrotCoinbase matches a Carrot coinbase from a list of outputs. Returns the absolute index of the matched output, scan data, and eligible address index if available
	// Slice outputs to continue scanning
	MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex)
}

type LegacyScan struct {
	Amount               uint64
	AmountBlindingFactor curve25519.PrivateKeyBytes

	ExtensionG curve25519.Scalar
	// ExtensionT Always zero
	ExtensionT curve25519.Scalar

	SpendPub curve25519.PublicKeyBytes

	PaymentId [monero.PaymentIdSize]byte
}

type ViewWalletLegacyInterface[T curve25519.PointOperations] interface {
	ViewWalletInterface[T]

	// GetFromSpend Like Get, but allows unknown spendPub to be derived
	GetFromSpend(spendPub *curve25519.PublicKey[T]) *address.Address

	// Match matches a legacy / non-Carrot coinbase or non-coinbase from a list of outputs. Returns the absolute index of the matched output, scan data, and eligible address index if available
	// Slice outputs to continue scanning
	//
	// Only available in non-Carrot legacy implementation
	Match(outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes) (index int, scan *LegacyScan, addressIndex address.SubaddressIndex)
}
