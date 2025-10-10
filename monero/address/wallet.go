package address

import (
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

type ViewWallet struct {
	addr          *Address
	viewKeyScalar *crypto.PrivateKeyScalar
	viewKeyBytes  crypto.PrivateKeyBytes
	// spendMap used to lookup spend keys to subaddress index
	spendMap map[crypto.PublicKeyBytes]SubaddressIndex
}

// NewViewWallet Creates a new ViewWallet with the specified account and index depth. The main address is always tracked
func NewViewWallet(a *Address, viewKey crypto.PrivateKey, accountDepth, indexDepth int) (*ViewWallet, error) {
	if a == nil || a.IsSubaddress() || !a.Valid() {
		return nil, errors.New("address must be a main valid one")
	}

	viewKeyScalar := viewKey.AsScalar()
	if viewKeyScalar == nil {
		return nil, errors.New("view key must be valid")
	}

	w := &ViewWallet{
		addr:          a,
		viewKeyScalar: viewKeyScalar,
		viewKeyBytes:  viewKeyScalar.AsBytes(),
		spendMap:      make(map[crypto.PublicKeyBytes]SubaddressIndex),
	}
	w.spendMap[a.SpendPub] = ZeroSubaddressIndex

	if accountDepth != 0 || indexDepth != 0 {
		for account := range accountDepth + 1 {
			for index := range indexDepth + 1 {
				if err := w.Track(SubaddressIndex{Account: uint32(account), Offset: uint32(index)}); err != nil {
					return nil, err
				}
			}
		}
	}

	return w, nil
}

// Track Adds the subaddress index to track map
func (w *ViewWallet) Track(ix SubaddressIndex) error {
	if ix != ZeroSubaddressIndex {
		sa := getSubaddress(w.addr, w.viewKeyScalar, w.viewKeyBytes, ix)
		if sa == nil {
			return errors.New("error generating subaddress")
		}
		w.spendMap[sa.SpendPub] = ix
	}
	return nil
}

// Match Matches a list of outputs from a transaction
func (w *ViewWallet) Match(outputs transaction.Outputs, txPubs ...crypto.PublicKeyBytes) (index int, txPub crypto.PublicKeyBytes, sharedData crypto.PrivateKey, addressIndex SubaddressIndex) {
	var sharedDataPub, ephemeralPub edwards25519.Point
	var err error
	var sharedDataScalar edwards25519.Scalar
	for _, pub := range txPubs {
		derivation := w.viewKeyBytes.GetDerivationCofactor(&pub).AsBytes()
		for _, out := range outputs {
			viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(&sharedDataScalar, derivation, out.Index)
			if out.Type == transaction.TxOutToTaggedKey && viewTag != out.ViewTag[0] {
				continue
			}

			sharedDataPub.UnsafeVarTimeScalarBaseMult(&sharedDataScalar)

			_, err = ephemeralPub.SetBytes(out.EphemeralPublicKey[:])
			if err != nil {
				return -1, crypto.PublicKeyBytes{}, nil, ZeroSubaddressIndex
			}

			D := ephemeralPub.Subtract(&ephemeralPub, &sharedDataPub)
			if ix, ok := w.HasSpend(crypto.PublicKeyBytes(D.Bytes())); ok {
				return int(out.Index), pub, crypto.PrivateKeyFromScalar(&sharedDataScalar), ix
			}
		}
	}

	return -1, crypto.PublicKeyBytes{}, nil, ZeroSubaddressIndex
}

func (w *ViewWallet) HasSpend(spendPub crypto.PublicKeyBytes) (SubaddressIndex, bool) {
	ix, ok := w.spendMap[spendPub]
	return ix, ok
}

func (w *ViewWallet) Get(index SubaddressIndex) *Address {
	return getSubaddress(w.addr, w.viewKeyScalar, w.viewKeyBytes, index)
}

func (w *ViewWallet) ViewKey() crypto.PrivateKey {
	return w.viewKeyScalar
}
