package address

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

// GetTxProofV2
// Deprecated
func GetTxProofV2(a Interface, txId types.Hash, txKey crypto.PrivateKey, message string) crypto.TxProof {
	return GetOutProofV2(a, txId, txKey, message)
}

// GetTxProofV1
// Deprecated
func GetTxProofV1(a Interface, txId types.Hash, txKey crypto.PrivateKey, message string) crypto.TxProof {
	return GetOutProofV1(a, txId, txKey, message)
}

func GetOutProofV2(a Interface, txId types.Hash, txKey crypto.PrivateKey, message string, additionalTxKeys ...crypto.PrivateKey) crypto.TxProof {
	prefixHash := crypto.Keccak256Var(txId[:], []byte(message))

	sharedSecret := make([]crypto.PublicKey, 1, 1+len(additionalTxKeys))
	signature := make([]crypto.Signature, 1, 1+len(additionalTxKeys))

	sharedSecret[0] = txKey.GetDerivation(a.ViewPublicKey())
	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		pub := txKey.GetDerivation(sa.SpendPublicKey())
		signature[0] = crypto.GenerateTxProofV2(prefixHash, pub.AsPoint(), sa.ViewPublicKey().AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[0].AsPoint(), txKey.AsScalar())
	} else {
		signature[0] = crypto.GenerateTxProofV2(prefixHash, txKey.PublicKey().AsPoint(), a.ViewPublicKey().AsPoint(), nil, sharedSecret[0].AsPoint(), txKey.AsScalar())
	}

	for i, additionalTxKey := range additionalTxKeys {
		sharedSecret[i+1] = additionalTxKey.GetDerivation(a.ViewPublicKey())
		if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
			pub := additionalTxKey.GetDerivation(sa.SpendPublicKey())
			signature[i+1] = crypto.GenerateTxProofV2(prefixHash, pub.AsPoint(), sa.ViewPublicKey().AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[i+1].AsPoint(), additionalTxKey.AsScalar())
		} else {
			signature[i+1] = crypto.GenerateTxProofV2(prefixHash, additionalTxKey.PublicKey().AsPoint(), a.ViewPublicKey().AsPoint(), nil, sharedSecret[i+1].AsPoint(), additionalTxKey.AsScalar())
		}
	}

	return crypto.NewTxProofFromSharedSecretSignaturePairs(crypto.OutProof, 2, sharedSecret, signature)
}

func GetOutProofV1(a Interface, txId types.Hash, txKey crypto.PrivateKey, message string, additionalTxKeys ...crypto.PrivateKey) crypto.TxProof {
	prefixHash := crypto.Keccak256Var(txId[:], []byte(message))

	sharedSecret := make([]crypto.PublicKey, 1, 1+len(additionalTxKeys))
	signature := make([]crypto.Signature, 1, 1+len(additionalTxKeys))

	sharedSecret[0] = txKey.GetDerivation(a.ViewPublicKey())
	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		signature[0] = crypto.GenerateTxProofV1(prefixHash, sa.ViewPublicKey().AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[0].AsPoint(), txKey.AsScalar())
	} else {
		signature[0] = crypto.GenerateTxProofV1(prefixHash, a.ViewPublicKey().AsPoint(), nil, sharedSecret[0].AsPoint(), txKey.AsScalar())
	}

	for i, additionalTxKey := range additionalTxKeys {
		sharedSecret[i+1] = additionalTxKey.GetDerivation(a.ViewPublicKey())
		if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
			signature[i+1] = crypto.GenerateTxProofV1(prefixHash, sa.ViewPublicKey().AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[i+1].AsPoint(), additionalTxKey.AsScalar())
		} else {
			signature[i+1] = crypto.GenerateTxProofV1(prefixHash, a.ViewPublicKey().AsPoint(), nil, sharedSecret[i+1].AsPoint(), additionalTxKey.AsScalar())
		}
	}

	return crypto.NewTxProofFromSharedSecretSignaturePairs(crypto.OutProof, 1, sharedSecret, signature)
}

func GetInProofV2(a Interface, txId types.Hash, viewKey crypto.PrivateKey, txPubKey crypto.PublicKey, message string, additionalTxPubKeys ...crypto.PublicKey) crypto.TxProof {
	prefixHash := crypto.Keccak256Var(txId[:], []byte(message))

	sharedSecret := make([]crypto.PublicKey, 1, 1+len(additionalTxPubKeys))
	signature := make([]crypto.Signature, 1, 1+len(additionalTxPubKeys))

	sharedSecret[0] = viewKey.GetDerivation(txPubKey)
	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		signature[0] = crypto.GenerateTxProofV2(prefixHash, sa.ViewPublicKey().AsPoint(), txPubKey.AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[0].AsPoint(), viewKey.AsScalar())
	} else {
		signature[0] = crypto.GenerateTxProofV2(prefixHash, a.ViewPublicKey().AsPoint(), txPubKey.AsPoint(), nil, sharedSecret[0].AsPoint(), viewKey.AsScalar())
	}

	for i, additionalTxPubKey := range additionalTxPubKeys {
		sharedSecret[i+1] = viewKey.GetDerivation(additionalTxPubKey)
		if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
			signature[i+1] = crypto.GenerateTxProofV2(prefixHash, sa.ViewPublicKey().AsPoint(), additionalTxPubKey.AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[i+1].AsPoint(), viewKey.AsScalar())
		} else {
			signature[i+1] = crypto.GenerateTxProofV2(prefixHash, a.ViewPublicKey().AsPoint(), additionalTxPubKey.AsPoint(), nil, sharedSecret[i+1].AsPoint(), viewKey.AsScalar())
		}
	}

	return crypto.NewTxProofFromSharedSecretSignaturePairs(crypto.InProof, 2, sharedSecret, signature)
}

func GetInProofV1(a Interface, txId types.Hash, viewKey crypto.PrivateKey, txPubKey crypto.PublicKey, message string, additionalTxPubKeys ...crypto.PublicKey) crypto.TxProof {
	prefixHash := crypto.Keccak256Var(txId[:], []byte(message))

	sharedSecret := make([]crypto.PublicKey, 1, 1+len(additionalTxPubKeys))
	signature := make([]crypto.Signature, 1, 1+len(additionalTxPubKeys))

	sharedSecret[0] = viewKey.GetDerivation(txPubKey)
	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		signature[0] = crypto.GenerateTxProofV1(prefixHash, txPubKey.AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[0].AsPoint(), viewKey.AsScalar())
	} else {
		signature[0] = crypto.GenerateTxProofV1(prefixHash, txPubKey.AsPoint(), nil, sharedSecret[0].AsPoint(), viewKey.AsScalar())
	}

	for i, additionalTxPubKey := range additionalTxPubKeys {
		sharedSecret[i+1] = viewKey.GetDerivation(additionalTxPubKey)
		if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
			signature[i+1] = crypto.GenerateTxProofV1(prefixHash, txPubKey.AsPoint(), sa.SpendPublicKey().AsPoint(), sharedSecret[i+1].AsPoint(), viewKey.AsScalar())
		} else {
			signature[i+1] = crypto.GenerateTxProofV1(prefixHash, txPubKey.AsPoint(), nil, sharedSecret[i+1].AsPoint(), viewKey.AsScalar())
		}
	}

	return crypto.NewTxProofFromSharedSecretSignaturePairs(crypto.InProof, 1, sharedSecret, signature)
}

func VerifyTxProof(proof crypto.TxProof, a Interface, txId types.Hash, txPubKey crypto.PublicKey, message string, additionalTxPubKeys ...crypto.PublicKey) (index int, ok bool) {
	prefixHash := crypto.Keccak256Var(txId[:], []byte(message))

	pubs := []crypto.PublicKey{
		txPubKey,
	}
	pubs = append(pubs, additionalTxPubKeys...)

	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		return proof.Verify(prefixHash, sa.ViewPublicKey(), sa.SpendPublicKey(), pubs...)
	} else {
		return proof.Verify(prefixHash, a.ViewPublicKey(), nil, pubs...)
	}
}
