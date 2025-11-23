package address

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/proofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func GetOutProof[T curve25519.PointOperations](a Interface, txId types.Hash, txKey *curve25519.Scalar, message string, version uint8, additionalTxKeys ...curve25519.Scalar) proofs.TxProof[T] {
	prefixHash := proofs.TxPrefixHash(txId, message)

	sharedSecret := make([]curve25519.PublicKey[T], 1+len(additionalTxKeys))
	signature := make([]crypto.Signature[T], 1+len(additionalTxKeys))

	var spendPub, viewPub curve25519.PublicKey[T]
	if _, err := spendPub.SetBytes(a.SpendPublicKey()[:]); err != nil {
		panic(err)
	}
	if _, err := viewPub.SetBytes(a.ViewPublicKey()[:]); err != nil {
		panic(err)
	}

	sharedSecret[0].ScalarMult(txKey, &viewPub)
	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		pub := new(curve25519.PublicKey[T]).ScalarMult(txKey, &spendPub)
		signature[0] = proofs.GenerateTxProof(prefixHash, pub, &viewPub, &spendPub, &sharedSecret[0], txKey, version)
	} else {
		pub := new(curve25519.PublicKey[T]).ScalarBaseMult(txKey)
		signature[0] = proofs.GenerateTxProof(prefixHash, pub, &viewPub, nil, &sharedSecret[0], txKey, version)
	}

	for i, additionalTxKey := range additionalTxKeys {
		sharedSecret[i+1].ScalarMult(&additionalTxKey, &viewPub)
		if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
			pub := new(curve25519.PublicKey[T]).ScalarMult(&additionalTxKey, &spendPub)
			signature[i+1] = proofs.GenerateTxProof(prefixHash, pub, &viewPub, &spendPub, &sharedSecret[i+1], txKey, version)
		} else {
			pub := new(curve25519.PublicKey[T]).ScalarBaseMult(&additionalTxKey)
			signature[i+1] = proofs.GenerateTxProof(prefixHash, pub, &viewPub, nil, &sharedSecret[i+1], txKey, version)
		}
	}

	return proofs.NewTxProofFromSharedSecretSignaturePairs(proofs.OutProof, version, sharedSecret, signature)
}

func GetInProof[T curve25519.PointOperations](a Interface, txId types.Hash, viewKey *curve25519.Scalar, txPubKey *curve25519.PublicKey[T], message string, version uint8, additionalTxPubKeys ...curve25519.PublicKey[T]) proofs.TxProof[T] {
	prefixHash := proofs.TxPrefixHash(txId, message)

	sharedSecret := make([]curve25519.PublicKey[T], 1+len(additionalTxPubKeys))
	signature := make([]crypto.Signature[T], 1+len(additionalTxPubKeys))

	var spendPub, viewPub curve25519.PublicKey[T]
	if _, err := spendPub.SetBytes(a.SpendPublicKey()[:]); err != nil {
		panic(err)
	}
	if _, err := viewPub.SetBytes(a.ViewPublicKey()[:]); err != nil {
		panic(err)
	}

	sharedSecret[0].ScalarMult(viewKey, txPubKey)
	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		signature[0] = proofs.GenerateTxProof(prefixHash, &viewPub, txPubKey, &spendPub, &sharedSecret[0], viewKey, version)
	} else {
		signature[0] = proofs.GenerateTxProof(prefixHash, &viewPub, txPubKey, nil, &sharedSecret[0], viewKey, version)
	}

	for i, additionalTxPubKey := range additionalTxPubKeys {
		sharedSecret[i+1].ScalarMult(viewKey, &additionalTxPubKey)
		if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
			signature[i+1] = proofs.GenerateTxProof(prefixHash, &viewPub, &additionalTxPubKey, &spendPub, &sharedSecret[i+1], viewKey, version)
		} else {
			signature[i+1] = proofs.GenerateTxProof(prefixHash, &viewPub, &additionalTxPubKey, nil, &sharedSecret[i+1], viewKey, version)
		}
	}

	return proofs.NewTxProofFromSharedSecretSignaturePairs(proofs.InProof, version, sharedSecret, signature)
}

func VerifyTxProof[T curve25519.PointOperations](proof proofs.TxProof[T], a Interface, txId types.Hash, txPubKey *curve25519.PublicKey[T], message string, additionalTxPubKeys ...curve25519.PublicKey[T]) (index int, ok bool) {
	prefixHash := proofs.TxPrefixHash(txId, message)

	pubs := []curve25519.PublicKey[T]{
		*txPubKey,
	}
	pubs = append(pubs, additionalTxPubKeys...)

	var viewPub curve25519.PublicKey[T]
	if _, err := viewPub.SetBytes(a.ViewPublicKey()[:]); err != nil {
		return -1, false
	}

	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		var spendPub curve25519.PublicKey[T]
		if _, err := spendPub.SetBytes(a.SpendPublicKey()[:]); err != nil {
			return -1, false
		}

		return proof.Verify(prefixHash, &viewPub, &spendPub, pubs...)
	} else {
		return proof.Verify(prefixHash, &viewPub, nil, pubs...)
	}
}
