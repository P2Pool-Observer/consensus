package wallet

import (
	"errors"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
)

func txPubs(extra transaction.ExtraTags) (pubs []curve25519.PublicKeyBytes) {

	if txPubExtra := extra.GetTag(transaction.TxExtraTagPubKey); txPubExtra != nil && len(txPubExtra.Data) == curve25519.PublicKeySize {
		// #nosec G103 -- verified public key size for data
		return unsafe.Slice((*curve25519.PublicKeyBytes)(unsafe.Pointer(unsafe.SliceData(txPubExtra.Data))), 1)
	}

	if txPubsExtra := extra.GetTag(transaction.TxExtraTagAdditionalPubKeys); txPubsExtra != nil && len(txPubsExtra.Data) > 0 && len(txPubsExtra.Data)%curve25519.PublicKeySize == 0 {
		// #nosec G103 -- verified public key size for data, and that it's modulo the data, and it's longer than 0
		return unsafe.Slice((*curve25519.PublicKeyBytes)(unsafe.Pointer(unsafe.SliceData(txPubsExtra.Data))), len(txPubsExtra.Data)/curve25519.PublicKeySize)
	}

	return nil
}

func MatchTransaction[T curve25519.PointOperations, ViewWallet ViewWalletInterface[T]](
	wallet ViewWallet,
	legacyMatch func(index int, scan *LegacyScan, ix address.SubaddressIndex),
	carrotMatch func(index int, scan *carrot.ScanV1, ix address.SubaddressIndex),
	tx transaction.PrunedTransaction,
) error {
	if len(tx.Outputs()) == 0 {
		return nil
	}

	extra := tx.ExtraTags()
	if len(extra) == 0 {
		return errors.New("no extra tags")
	}
	pubs := txPubs(tx.ExtraTags())
	if len(pubs) == 0 {
		return errors.New("no valid public keys")
	}

	var commitments []ringct.CommitmentEncryptedAmount

	// is coinbase check
	isCoinbase := len(tx.Inputs()) == 0
	var blockIndex uint64

	if isCoinbase {
		if txv2, ok := tx.(*transaction.CoinbaseV2); ok {
			blockIndex = txv2.GenHeight
		} else if genTx, ok := tx.(*transaction.GenericCoinbase); ok {
			blockIndex = genTx.GenHeight
		} else {
			return errors.New("cannot get coinbase block height")
		}
	} else {
		if txv2, ok := tx.(*transaction.TransactionV2); ok {
			commitments = make([]ringct.CommitmentEncryptedAmount, len(txv2.Outputs()))
			for i := range txv2.Outputs() {
				commitments[i].Commitment = txv2.Commitments[i]
				commitments[i].EncryptedAmount = txv2.EncryptedAmounts[i]
			}
		}
		// txv1 do not have commitments
	}

	switch tx.Outputs()[0].Type {
	case transaction.TxOutToCarrotV1:
		if carrotMatch == nil {
			return nil
		}

		var i int
		var scan *carrot.ScanV1
		var ix address.SubaddressIndex
		for i != -1 && i < len(tx.Outputs()) {
			if isCoinbase {
				i, scan, ix = wallet.MatchCarrotCoinbase(blockIndex, tx.Outputs()[i:], pubs)
			} else {
				i, scan, ix = wallet.MatchCarrot(tx.Inputs()[0].KeyImage, tx.Outputs()[i:], commitments, pubs)
			}
			if i != -1 {
				carrotMatch(i, scan, ix)
				i++
			}
		}
	case transaction.TxOutToKey, transaction.TxOutToTaggedKey:
		if legacyMatch == nil {
			return nil
		}
		if legacyWallet, ok := any(wallet).(ViewWalletLegacyInterface[T]); ok {
			var i int
			var scan *LegacyScan
			var ix address.SubaddressIndex
			for i != -1 && i < len(tx.Outputs()) {
				if i, scan, ix = legacyWallet.Match(tx.Outputs()[i:], commitments, pubs); i != -1 {
					legacyMatch(i, scan, ix)
					i++
				}
			}
		}

	}
	return nil
}
