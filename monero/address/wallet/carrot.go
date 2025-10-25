package wallet

import (
	"errors"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

func NewCarrotViewWalletFromMasterSecret(masterSecret types.Hash, addressNetwork uint8, accountDepth, indexDepth int) (*CarrotViewWallet, error) {
	var hasher blake2b.Digest

	// todo: use this in other parts
	var proveSpend crypto.PrivateKeyScalar
	carrot.MakeProveSpendKey(&hasher, &proveSpend, masterSecret)

	// precompute
	var proveSpendPub edwards25519.Point
	proveSpendPub.UnsafeVarTimeScalarMultPrecomputed(proveSpend.Scalar(), crypto.GeneratorT.Table)

	viewBalanceSecret := carrot.MakeViewBalanceSecret(&hasher, masterSecret)
	return NewCarrotViewWalletFromViewBalanceSecret(crypto.PublicKeyFromPoint(&proveSpendPub), viewBalanceSecret, addressNetwork, accountDepth, indexDepth)
}

func NewCarrotViewWalletFromViewBalanceSecret(proveSpendPub crypto.PublicKey, viewBalanceSecret types.Hash, addressNetwork uint8, accountDepth, indexDepth int) (*CarrotViewWallet, error) {
	var hasher blake2b.Digest

	var generateImage, viewIncoming crypto.PrivateKeyScalar
	carrot.MakeGenerateImageKey(&hasher, &generateImage, viewBalanceSecret)
	generateAddressSecret := carrot.MakeGenerateAddressSecret(&hasher, viewBalanceSecret)
	carrot.MakeViewIncomingKey(&hasher, &viewIncoming, viewBalanceSecret)

	var spendPub crypto.PublicKeyPoint
	carrot.MakeSpendPubFromSpendPub(&spendPub, &generateImage, proveSpendPub.AsPoint())

	return NewCarrotViewWallet(
		address.FromRawAddress(addressNetwork, proveSpendPub, viewIncoming.PublicKey()),
		&generateImage,
		&viewIncoming,
		generateAddressSecret,
		accountDepth,
		indexDepth,
	)
}

type CarrotViewWallet struct {
	primaryAddress *address.Address
	// generateImageKeyScalar can be nil
	generateImageKeyScalar *crypto.PrivateKeyScalar
	viewIncomingKey        crypto.PrivateKeyBytes

	generateAddressSecret types.Hash

	// carrot public keys (minus K^0_v, which is shared with legacy K^0_v)
	accountSpendPub crypto.PublicKeyPoint
	accountViewPub  crypto.PublicKeyPoint

	// spendMap used to lookup spend keys to subaddress index
	spendMap map[crypto.PublicKeyBytes]address.SubaddressIndex
}

// NewCarrotViewWallet Creates a new CarrotViewWallet with the specified account and index depth. The main address is always tracked
func NewCarrotViewWallet(primaryAddress *address.Address, generateImageKey, viewIncomingKey crypto.PrivateKey, generateAddressSecret types.Hash, accountDepth, indexDepth int) (*CarrotViewWallet, error) {
	if primaryAddress == nil || primaryAddress.IsSubaddress() || !primaryAddress.Valid() {
		return nil, errors.New("address must be a main valid one")
	}

	viewIncomingKeyScalar := viewIncomingKey.AsScalar()
	if viewIncomingKeyScalar == nil {
		return nil, errors.New("view incoming key must be valid")
	}

	if generateAddressSecret == types.ZeroHash {
		return nil, errors.New("generate address secret must be non-zero")
	}

	if viewIncomingKeyScalar.PublicKey().AsBytes() != *primaryAddress.ViewPublicKey() {
		return nil, errors.New("view incoming key public must be equal to primary address pub key")
	}

	accountSpendPub := primaryAddress.SpendPublicKey().AsPoint()

	var accountViewPub crypto.PublicKeyPoint
	carrot.MakeAccountViewPub(&accountViewPub, viewIncomingKeyScalar, accountSpendPub)

	w := &CarrotViewWallet{
		primaryAddress:        primaryAddress,
		accountViewPub:        accountViewPub,
		accountSpendPub:       *accountSpendPub,
		viewIncomingKey:       viewIncomingKey.AsBytes(),
		generateAddressSecret: generateAddressSecret,
		spendMap:              make(map[crypto.PublicKeyBytes]address.SubaddressIndex),
	}

	if generateImageKey != nil {
		w.generateImageKeyScalar = generateImageKey.AsScalar()
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
func (w *CarrotViewWallet) Track(ix address.SubaddressIndex) error {
	var hasher blake2b.Digest
	return w.track(&hasher, ix)
}

func (w *CarrotViewWallet) track(hasher *blake2b.Digest, ix address.SubaddressIndex) error {
	if ix == address.ZeroSubaddressIndex {
		return nil
	}

	w.spendMap[carrot.MakeDestinationSubaddressSpendPub(hasher, &w.accountSpendPub, w.generateAddressSecret, ix)] = ix
	return nil
}

func (w *CarrotViewWallet) MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
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

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(w.viewIncomingKey, enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *CarrotViewWallet) MatchCarrot(firstKeyImage crypto.PublicKeyBytes, commitments []crypto.RCTAmount, outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
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

			senderReceiverUnctx := carrot.MakeUncontextualizedSharedKeyReceiver(w.viewIncomingKey, enote.EphemeralPubKey)
			if enote.TryScanEnoteChecked(scan, inputContext[:], senderReceiverUnctx, w.primaryAddress.SpendPub) == nil {
				if ix, ok := w.HasSpend(scan.SpendPub); ok {
					return int(out.Index), scan, ix
				}
			}
		}
	}
	return -1, nil, address.ZeroSubaddressIndex
}

func (w *CarrotViewWallet) HasSpend(spendPub crypto.PublicKeyBytes) (address.SubaddressIndex, bool) {
	ix, ok := w.spendMap[spendPub]
	return ix, ok
}

func (w *CarrotViewWallet) Get(index address.SubaddressIndex) *address.Address {
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
		return address.FromRawAddress(monero.SubAddressMainNetwork, sa.Address.SpendPublicKey(), sa.Address.ViewPublicKey())
	case monero.TestNetwork:
		return address.FromRawAddress(monero.SubAddressTestNetwork, sa.Address.SpendPublicKey(), sa.Address.ViewPublicKey())
	case monero.StageNetwork:
		return address.FromRawAddress(monero.SubAddressStageNetwork, sa.Address.SpendPublicKey(), sa.Address.ViewPublicKey())
	default:
		return nil
	}
}

func (w *CarrotViewWallet) GenerateImageKey() crypto.PrivateKey {
	return w.generateImageKeyScalar
}

func (w *CarrotViewWallet) GenerateAddressSecret() types.Hash {
	return w.generateAddressSecret
}

func (w *CarrotViewWallet) ViewIncomingKey() crypto.PrivateKey {
	return &w.viewIncomingKey
}
