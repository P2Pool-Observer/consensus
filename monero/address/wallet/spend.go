package wallet

import (
	"errors"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/cryptonote"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type CarrotSpendWallet[T curve25519.PointOperations] struct {
	vw                          CarrotViewWallet[T]
	generateImagePreimageSecret types.Hash
	partialSpendPub             curve25519.PublicKey[T]
	proveSpendScalar            curve25519.Scalar
}

func (w *CarrotSpendWallet[T]) Get(ix address.SubaddressIndex) *address.Address {
	return w.vw.Get(ix)
}

func (w *CarrotSpendWallet[T]) Track(ix address.SubaddressIndex) error {
	return w.vw.Track(ix)
}

func (w *CarrotSpendWallet[T]) HasSpend(spendPub curve25519.PublicKeyBytes) (address.SubaddressIndex, bool) {
	return w.vw.HasSpend(spendPub)
}

func (w *CarrotSpendWallet[T]) MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	return w.vw.MatchCarrot(firstKeyImage, outputs, commitments, txPubs)
}

func (w *CarrotSpendWallet[T]) MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	return w.vw.MatchCarrotCoinbase(blockIndex, outputs, txPubs)
}

func (w *CarrotSpendWallet[T]) ProveSpendKey() *curve25519.Scalar {
	return &w.proveSpendScalar
}

func (w *CarrotSpendWallet[T]) PartialSpendPub() *curve25519.PublicKey[T] {
	return &w.partialSpendPub
}

func (w *CarrotSpendWallet[T]) GenerateImagePreimageSecret() types.Hash {
	return w.generateImagePreimageSecret
}

func (w *CarrotSpendWallet[T]) ViewWallet() *CarrotViewWallet[T] {
	return &w.vw
}

func (w *CarrotSpendWallet[T]) Opening(index address.SubaddressIndex) (keyG, keyT *curve25519.Scalar, spendPub *curve25519.PublicKey[T]) {
	// needs generate image key
	if w.vw.GenerateImageKey() == nil {
		return nil, nil, nil
	}

	var subaddressScalar curve25519.Scalar
	if !index.IsZero() {
		var hasher blake2b.Digest
		// s^j_ap1 = H_32[s_ga](j_major, j_minor)
		addressIndexPreimage1 := carrot.MakeAddressIndexPreimage1(&hasher, w.vw.GenerateAddressSecret(), index)

		accountSpendPubBytes := w.vw.AccountSpendPub().AsBytes()

		// s^j_ap2 = H_32[s^j_ap1](j_major, j_minor, K_s, K_v)
		addressIndexPreimage2 := carrot.MakeAddressIndexPreimage2(&hasher, addressIndexPreimage1, accountSpendPubBytes, w.vw.AccountViewPub().AsBytes(), index)

		// k^j_subscal = H_n[s^j_gen](K_s, K_v, j_major, j_minor)
		carrot.MakeSubaddressScalar(&hasher, &subaddressScalar, addressIndexPreimage2, accountSpendPubBytes)
	} else {
		// k^j_subscal = 1
		subaddressScalar.Set((&curve25519.PrivateKeyBytes{1}).Scalar())
	}

	keyG = new(curve25519.Scalar).Multiply(w.vw.GenerateImageKey(), &subaddressScalar)
	keyT = new(curve25519.Scalar).Multiply(&w.proveSpendScalar, &subaddressScalar)

	// x G + y T
	spendPub = new(curve25519.PublicKey[T]).DoubleScalarBaseMultPrecomputed(keyT, crypto.GeneratorT, keyG)

	return keyG, keyT, spendPub
}

func NewCarrotSpendWalletFromMasterSecret[T curve25519.PointOperations](masterSecret types.Hash, addressNetwork uint8, accountDepth, indexDepth int) (*CarrotSpendWallet[T], error) {
	var hasher blake2b.Digest

	var proveSpend curve25519.Scalar
	carrot.MakeProveSpendKey(&hasher, &proveSpend, masterSecret)

	var partialSpendPub curve25519.PublicKey[T]
	carrot.MakePartialSpendPub(&partialSpendPub, &proveSpend)

	viewBalanceSecret := carrot.MakeViewBalanceSecret(&hasher, masterSecret)
	vw, err := NewCarrotViewWalletFromViewBalanceSecret(&partialSpendPub, viewBalanceSecret, addressNetwork, accountDepth, indexDepth)
	if err != nil {
		return nil, err
	}

	return &CarrotSpendWallet[T]{
		vw:                          *vw,
		generateImagePreimageSecret: carrot.MakeGenerateImagePreimageSecret(&hasher, viewBalanceSecret),
		partialSpendPub:             partialSpendPub,
		proveSpendScalar:            proveSpend,
	}, nil
}

type SpendWallet[T curve25519.PointOperations] struct {
	vw             ViewWallet[T]
	spendKeyScalar curve25519.Scalar
}

func (w *SpendWallet[T]) Get(ix address.SubaddressIndex) *address.Address {
	return w.vw.Get(ix)
}

func (w *SpendWallet[T]) Track(ix address.SubaddressIndex) error {
	return w.vw.Track(ix)
}

func (w *SpendWallet[T]) HasSpend(spendPub curve25519.PublicKeyBytes) (address.SubaddressIndex, bool) {
	return w.vw.HasSpend(spendPub)
}

func (w *SpendWallet[T]) MatchCarrot(firstKeyImage curve25519.PublicKeyBytes, outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	return w.vw.MatchCarrot(firstKeyImage, outputs, commitments, txPubs)
}

func (w *SpendWallet[T]) MatchCarrotCoinbase(blockIndex uint64, outputs transaction.Outputs, txPubs []curve25519.PublicKeyBytes) (index int, scan *carrot.ScanV1, addressIndex address.SubaddressIndex) {
	return w.vw.MatchCarrotCoinbase(blockIndex, outputs, txPubs)
}

func (w *SpendWallet[T]) Match(outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes) (index int, scan *LegacyScan, addressIndex address.SubaddressIndex) {
	return w.vw.Match(outputs, commitments, txPubs)
}

func (w *SpendWallet[T]) SpendKey() *curve25519.Scalar {
	return &w.spendKeyScalar
}

func (w *SpendWallet[T]) ViewWallet() *ViewWallet[T] {
	return &w.vw
}

func (w *SpendWallet[T]) Opening(index address.SubaddressIndex) (keyG, keyT *curve25519.Scalar, spendPub *curve25519.PublicKey[T]) {
	// m = Hn(k_v || j_major || j_minor) if subaddress else 0
	subaddressExtension := cryptonote.SubaddressExtension(new(curve25519.Scalar), index, curve25519.PrivateKeyBytes(w.vw.ViewKey().Bytes()))

	keyG = new(curve25519.Scalar).Add(&w.spendKeyScalar, subaddressExtension)
	keyT = new(curve25519.Scalar)

	// x G + y T
	spendPub = new(curve25519.PublicKey[T]).DoubleScalarBaseMultPrecomputed(keyT, crypto.GeneratorT, keyG)

	return keyG, keyT, spendPub
}

func NewSpendWalletFromSpendKey[T curve25519.PointOperations](spendKey *curve25519.Scalar, addressNetwork uint8, accountDepth, indexDepth int) (*SpendWallet[T], error) {
	var viewKey curve25519.Scalar
	crypto.ScalarDeriveLegacy(&viewKey, spendKey.Bytes())
	var spendPub, viewPub curve25519.PublicKey[T]
	spendPub.ScalarBaseMult(spendKey)
	viewPub.ScalarBaseMult(&viewKey)
	vw, err := NewViewWallet[T](address.FromRawAddress(addressNetwork, spendPub.AsBytes(), viewPub.AsBytes()), &viewKey, accountDepth, indexDepth)
	if err != nil {
		return nil, err
	}
	return &SpendWallet[T]{
		vw:             *vw,
		spendKeyScalar: *spendKey,
	}, nil
}

var ErrNoSpendPub = errors.New("wallet is not tracking spend pub")
var ErrCannotRecomputeSpendPub = errors.New("cannot recompute spend pub")

func TrySearchForOpeningForSubaddress[T curve25519.PointOperations, SpendWallet SpendWalletInterface[T]](wallet SpendWallet, spendPub *curve25519.PublicKey[T]) (keyG, keyT *curve25519.Scalar, err error) {
	index, ok := wallet.HasSpend(spendPub.AsBytes())
	if !ok {
		return nil, nil, ErrNoSpendPub
	}
	var recomputedSpendPub *curve25519.PublicKey[T]
	keyG, keyT, recomputedSpendPub = wallet.Opening(index)

	if recomputedSpendPub == nil || spendPub.Equal(recomputedSpendPub) == 0 {
		return nil, nil, ErrCannotRecomputeSpendPub
	}

	return keyG, keyT, nil
}

func TrySearchForOpeningForOneTimeAddress[T curve25519.PointOperations, SpendWallet SpendWalletInterface[T]](wallet SpendWallet, spendPub *curve25519.PublicKey[T], senderExtensionG, senderExtensionT *curve25519.Scalar) (x, y *curve25519.Scalar, err error) {
	// k^{j,g}_addr, k^{j,t}_addr
	keyG, keyT, err := TrySearchForOpeningForSubaddress(wallet, spendPub)
	if err != nil {
		return nil, nil, err
	}

	// x = k^{j,g}_addr + k^g_o
	x = new(curve25519.Scalar).Add(keyG, senderExtensionG)

	// y = k^{j,t}_addr + k^t_o
	y = new(curve25519.Scalar).Add(keyT, senderExtensionT)

	return x, y, nil
}

var ErrCannotRecomputeOneTimeAddressFromExtension = errors.New("cannot recompute one time address from extension")
var ErrCannotRecomputeOneTimeAddressFromOpening = errors.New("cannot recompute one time address from opening")

// CanOpenOneTimeAddress can_open_fcmp_onetime_address
func CanOpenOneTimeAddress[T curve25519.PointOperations, SpendWallet SpendWalletInterface[T]](wallet SpendWallet, spendPub *curve25519.PublicKey[T], senderExtensionG, senderExtensionT *curve25519.Scalar, oneTimeAddress *curve25519.PublicKey[T]) error {
	senderExtensionPub := new(curve25519.PublicKey[T]).DoubleScalarBaseMultPrecomputed(senderExtensionT, crypto.GeneratorT, senderExtensionG)

	recomputedOneTimeAddress := new(curve25519.PublicKey[T]).Add(spendPub, senderExtensionPub)

	if oneTimeAddress.Equal(recomputedOneTimeAddress) == 0 {
		return ErrCannotRecomputeOneTimeAddressFromExtension
	}

	x, y, err := TrySearchForOpeningForOneTimeAddress(wallet, spendPub, senderExtensionG, senderExtensionT)
	if err != nil {
		return err
	}

	// O' = x G + y T
	recomputedOneTimeAddress = new(curve25519.PublicKey[T]).DoubleScalarBaseMultPrecomputed(y, crypto.GeneratorT, x)

	// O' ?= O
	if oneTimeAddress.Equal(recomputedOneTimeAddress) == 0 {
		return ErrCannotRecomputeOneTimeAddressFromOpening
	}
	return nil
}
