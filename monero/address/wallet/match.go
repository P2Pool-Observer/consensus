package wallet

import (
	"crypto/subtle"
	"errors"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/proofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
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

func txPaymentId(extra transaction.ExtraTags) (paymentId, encryptedPaymentId *[monero.PaymentIdSize]byte) {
	nonce := extra.GetTag(transaction.TxExtraTagNonce)
	if nonce == nil || len(nonce.Data) != monero.PaymentIdSize+1 {
		return nil, nil
	}

	if nonce.Data[0] == transaction.TxExtraNoncePaymentId {
		return (*[monero.PaymentIdSize]byte)(nonce.Data[1:]), nil
	} else if nonce.Data[1] == transaction.TxExtraNonceEncryptedPaymentId {
		return nil, (*[monero.PaymentIdSize]byte)(nonce.Data[1:])
	}
	return nil, nil
}

func MatchTransactionProof[T curve25519.PointOperations](
	addr address.InterfaceSubaddress,
	proof proofs.TxProof[T], message string,
	legacyMatch func(index int, scan *LegacyScan, _ address.SubaddressIndex),
	carrotMatch func(index int, scan *carrot.ScanV1, _ address.SubaddressIndex),
	txId types.Hash,
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

	if len(tx.Outputs()) == 0 {
		return errors.New("no valid outputs")
	}

	encryptedPaymentId, paymentId := txPaymentId(extra)

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

	var spendPub, viewPub curve25519.PublicKey[T]
	if _, err := spendPub.SetBytes(addr.SpendPublicKey()[:]); err != nil {
		return err
	}
	if _, err := viewPub.SetBytes(addr.ViewPublicKey()[:]); err != nil {
		return err
	}

	switch tx.Outputs()[0].Type {
	case transaction.TxOutToCarrotV1:
		if carrotMatch == nil {
			return nil
		}

		_ = blockIndex

		// TODO!
	case transaction.TxOutToKey, transaction.TxOutToTaggedKey:
		if legacyMatch == nil {
			return nil
		}
		var i int
		var scan *LegacyScan
		for i != -1 && i < len(tx.Outputs()) {
			if i, scan = matchTxProof(proof, txId, message, addr, &spendPub, tx.Outputs()[i:], commitments, pubs, encryptedPaymentId); i != -1 {
				if paymentId != nil {
					scan.PaymentId = *paymentId
				}
				legacyMatch(i, scan, address.UnknownSubaddressIndex)
				i++
			}
		}
	}
	return nil
}
func matchTxProof[T curve25519.PointOperations](proof proofs.TxProof[T], txId types.Hash, message string, a address.InterfaceSubaddress, spendPub *curve25519.PublicKey[T], outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes, encryptedPaymentId *[monero.PaymentIdSize]byte) (index int, scan *LegacyScan) {
	var err error

	pubs := make([]curve25519.PublicKey[T], len(txPubs))
	for i := range txPubs {
		if _, err = pubs[i].SetBytes(txPubs[i][:]); err != nil {
			return -1, nil
		}
	}

	index, ok := address.VerifyTxProof(proof, a, txId, &pubs[0], message, pubs[1:]...)
	if !ok {
		return -1, nil
	}

	derivation := new(curve25519.PublicKey[T]).MultByCofactor(&proof.Claims[index].SharedSecret).AsBytes()

	for i := range outputs {
		if index, scan = matchDerivation(derivation, spendPub, &outputs[i], commitments, encryptedPaymentId); index != -1 {
			return index, scan
		}
	}

	return -1, nil
}

func MatchTransactionKey[T curve25519.PointOperations](
	addr address.InterfaceSubaddress,
	txKey *curve25519.Scalar,
	legacyMatch func(index int, scan *LegacyScan, _ address.SubaddressIndex),
	carrotMatch func(index int, scan *carrot.ScanV1, _ address.SubaddressIndex),
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

	if len(tx.Outputs()) == 0 {
		return errors.New("no valid outputs")
	}

	encryptedPaymentId, paymentId := txPaymentId(extra)

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

	var expectedPub curve25519.PublicKeyBytes
	var spendPub, viewPub curve25519.PublicKey[T]
	if _, err := spendPub.SetBytes(addr.SpendPublicKey()[:]); err != nil {
		return err
	}
	if _, err := viewPub.SetBytes(addr.ViewPublicKey()[:]); err != nil {
		return err
	}
	if addr.IsSubaddress() {
		expectedPub = new(curve25519.PublicKey[T]).ScalarMult(txKey, &spendPub).AsBytes()
	} else {
		expectedPub = new(curve25519.PublicKey[T]).ScalarBaseMult(txKey).AsBytes()
	}

	derivation := address.GetDerivation(new(curve25519.PublicKey[T]), &viewPub, txKey).AsBytes()

	switch tx.Outputs()[0].Type {
	case transaction.TxOutToCarrotV1:
		if carrotMatch == nil {
			return nil
		}

		_ = blockIndex

		// TODO!
	case transaction.TxOutToKey, transaction.TxOutToTaggedKey:
		if legacyMatch == nil {
			return nil
		}
		var i int
		var scan *LegacyScan
		for i != -1 && i < len(tx.Outputs()) {
			if i, scan = matchTxKey(expectedPub, derivation, &spendPub, tx.Outputs()[i:], commitments, pubs, encryptedPaymentId); i != -1 {
				if paymentId != nil {
					scan.PaymentId = *paymentId
				}
				legacyMatch(i, scan, address.UnknownSubaddressIndex)
				i++
			}
		}
	}
	return nil
}

func matchDerivation[T curve25519.PointOperations](derivation curve25519.PublicKeyBytes, spendPub *curve25519.PublicKey[T], out *transaction.Output, commitments []ringct.CommitmentEncryptedAmount, encryptedPaymentId *[monero.PaymentIdSize]byte) (index int, scan *LegacyScan) {
	if out.Type != transaction.TxOutToKey && out.Type != transaction.TxOutToTaggedKey {
		return -1, nil
	}

	var extensionG curve25519.Scalar

	_, viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndex(&extensionG, derivation, out.Index)
	if out.Type == transaction.TxOutToTaggedKey && viewTag != out.ViewTag.Slice()[0] {
		return -1, nil
	}
	var sharedDataPub, ephemeralPub curve25519.PublicKey[T]

	sharedDataPub.ScalarBaseMult(&extensionG)

	_, err := ephemeralPub.P().SetBytes(out.EphemeralPublicKey[:])
	if err != nil {
		return -1, nil
	}

	D := ephemeralPub.Subtract(&ephemeralPub, &sharedDataPub)
	if D.Equal(spendPub) == 1 {

		extensionGBytes := curve25519.PrivateKeyBytes(extensionG.Bytes())

		scan = &LegacyScan{
			ExtensionG: extensionG,
			// zero
			ExtensionT: curve25519.Scalar{},
			SpendPub:   D.AsBytes(),
		}
		if len(commitments) > int(out.Index) {
			c := commitments[int(out.Index)]
			lc := c.Decode(extensionGBytes, c.Mask == curve25519.ZeroPrivateKeyBytes)
			if ringct.CalculateCommitment(new(curve25519.PublicKey[T]), lc).AsBytes() != c.Commitment {
				// cannot match!
				return -1, nil
			}
			scan.Amount = lc.Amount
			copy(scan.AmountBlindingFactor[:], lc.Mask.Bytes())
		} else if out.Amount > 0 {
			// probably coinbase or old
			scan.Amount = out.Amount
			copy(scan.AmountBlindingFactor[:], ringct.CoinbaseAmountBlindingFactor.Bytes())
		}

		if encryptedPaymentId != nil {
			// restore payment id if any
			paymentIdKey := address.CalculatePaymentIdEncodingKey(extensionGBytes)
			subtle.XORBytes(scan.PaymentId[:], encryptedPaymentId[:], paymentIdKey[:])
		}

		return int(out.Index), scan
	}

	return -1, nil
}

func matchTxKey[T curve25519.PointOperations](expectedPub, derivation curve25519.PublicKeyBytes, spendPub *curve25519.PublicKey[T], outputs transaction.Outputs, commitments []ringct.CommitmentEncryptedAmount, txPubs []curve25519.PublicKeyBytes, encryptedPaymentId *[monero.PaymentIdSize]byte) (index int, scan *LegacyScan) {
	for _, pub := range txPubs {
		if expectedPub != pub {
			continue
		}

		for i := range outputs {
			if index, scan = matchDerivation(derivation, spendPub, &outputs[i], commitments, encryptedPaymentId); index != -1 {
				return index, scan
			}
		}
	}

	return -1, nil
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

	encryptedPaymentId, paymentId := txPaymentId(extra)

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
				i, scan, ix = wallet.MatchCarrot(tx.Inputs()[0].KeyImage, tx.Outputs()[i:], commitments, pubs, encryptedPaymentId)
			}
			if i != -1 {
				if paymentId != nil {
					scan.PaymentId = *paymentId
				}
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
				if i, scan, ix = legacyWallet.Match(tx.Outputs()[i:], commitments, pubs, encryptedPaymentId); i != -1 {
					if paymentId != nil {
						scan.PaymentId = *paymentId
					}
					legacyMatch(i, scan, ix)
					i++
				}
			}
		}

	}
	return nil
}
