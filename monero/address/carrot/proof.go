package carrot

import (
	"crypto/subtle"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/proofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519/field" //nolint:depguard
)

func GetTxProofNormal[T curve25519.PointOperations](a address.Interface, txId types.Hash, message string, inputContext []byte, proposal *PaymentProposalV1[T]) proofs.TxProof[T] {
	prefixHash := proofs.TxPrefixHash(txId, message)

	sharedSecret := make([]curve25519.PublicKeyBytes, 1)
	signature := make([]crypto.Signature[T], 1)

	var spendPub, viewPub curve25519.PublicKey[T]
	if _, err := spendPub.SetBytes(a.SpendPublicKey()[:]); err != nil {
		panic(err)
	}
	if _, err := viewPub.SetBytes(a.ViewPublicKey()[:]); err != nil {
		panic(err)
	}
	var hasher blake2b.Digest
	var ephemeralPrivateKey curve25519.Scalar

	makeEnoteEphemeralPrivateKey(&hasher, &ephemeralPrivateKey, proposal.Randomness[:], inputContext, *a.SpendPublicKey(), proposal.Destination.PaymentId)

	senderReceiverUnctx := makeUncontextualizedSharedKeySender[T](&ephemeralPrivateKey, &viewPub)

	sharedSecret[0] = curve25519.PublicKeyBytes(senderReceiverUnctx)
	if sa, ok := a.(address.InterfaceSubaddress); ok && sa.IsSubaddress() {
		signature[0] = GenerateTxProofNormal(prefixHash, &viewPub, &spendPub, &ephemeralPrivateKey)
	} else {
		signature[0] = GenerateTxProofNormal(prefixHash, &viewPub, nil, &ephemeralPrivateKey)
	}

	return proofs.NewTxProofFromSharedSecretBytesSignaturePairs(proofs.OutProof, 2, sharedSecret, signature)
}

func GenerateTxProofNormal[T curve25519.PointOperations](prefixHash types.Hash, A, B *curve25519.PublicKey[T], r *curve25519.Scalar) (signature crypto.Signature[T]) {
	var R, D curve25519.PublicKey[T]
	if B != nil {
		R.ScalarMult(r, B)
	} else {
		R.ScalarBaseMult(r)
	}

	// always force R's Ed25519 map to be positive, which means negating `r` if appropriate
	// constant time

	RIsNegative := subtle.ConstantTimeByteEq(R.Bytes()[31]&0x80, 0x80)
	// R = -R
	R.P().Select(new(curve25519.Point).Negate(R.P()), R.P(), RIsNegative)
	// r = -r
	r = new(curve25519.Scalar).Select(new(curve25519.Scalar).Negate(r), r, RIsNegative)

	// calculate D in Ed25519 according to possibly negated `r`
	D.ScalarMult(r, A)

	return proofs.GenerateTxProof(prefixHash, &R, A, B, &D, r, 2)
}

func GetTxProofReceiver[T curve25519.PointOperations](a address.Interface, txId types.Hash, message string, inputContext []byte, ephemeralPubKey curve25519.MontgomeryPoint, viewIncoming *curve25519.Scalar) proofs.TxProof[T] {
	prefixHash := proofs.TxPrefixHash(txId, message)

	sharedSecret := make([]curve25519.PublicKeyBytes, 1)
	signature := make([]crypto.Signature[T], 1)

	var spendPub curve25519.PublicKey[T]
	if _, err := spendPub.SetBytes(a.SpendPublicKey()[:]); err != nil {
		panic(err)
	}

	senderReceiverUnctx := MakeUncontextualizedSharedKeyReceiver(viewIncoming, &ephemeralPubKey)

	sharedSecret[0] = curve25519.PublicKeyBytes(senderReceiverUnctx)
	if sa, ok := a.(address.InterfaceSubaddress); ok && sa.IsSubaddress() {
		signature[0] = GenerateTxProofReceiver[T](prefixHash, ephemeralPubKey, &spendPub, viewIncoming)
	} else {
		signature[0] = GenerateTxProofReceiver[T](prefixHash, ephemeralPubKey, nil, viewIncoming)
	}

	return proofs.NewTxProofFromSharedSecretBytesSignaturePairs(proofs.InProof, 2, sharedSecret, signature)
}

func GenerateTxProofReceiver[T curve25519.PointOperations](prefixHash types.Hash, R curve25519.MontgomeryPoint, B *curve25519.PublicKey[T], a *curve25519.Scalar) (signature crypto.Signature[T]) {
	var R_ed25519, A, D curve25519.PublicKey[T]

	{
		var u field.Element
		_, _ = u.SetBytes(R.Slice())

		_, err := curve25519.DecodeMontgomeryPoint(&R_ed25519, &u, 0)
		if err != nil {
			panic(err)
		}
	}

	if B != nil {
		// A = a B
		A.ScalarMult(a, B)
	} else {
		// A = a G_ed
		A.ScalarBaseMult(a)
	}

	// D_ed = a R
	D.ScalarMult(a, &R_ed25519)

	return proofs.GenerateTxProof(prefixHash, &A, &R_ed25519, B, &D, a, 2)
}
