package address

import (
	"encoding/binary"
	"strings"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	base58 "git.gammaspectra.live/P2Pool/monero-base58"
)

var zeroKeyPub = new(curve25519.VarTimePublicKey).ScalarBaseMult(curve25519.ZeroPrivateKeyBytes.Scalar())

// ZeroKeyAddress Special address with private keys set to both zero.
// Useful to detect unsupported signatures from hardware wallets on Monero GUI
var ZeroKeyAddress = PackedAddress{
	zeroKeyPub.Bytes(),
	zeroKeyPub.Bytes(),
}

func GetPrivateKeyForSharedData(spendKey, sharedData *curve25519.Scalar) *curve25519.Scalar {
	return new(curve25519.Scalar).Add(sharedData, spendKey)
}

func GetPublicKeyForSharedData[T curve25519.PointOperations](out, spendPub *curve25519.PublicKey[T], sharedData *curve25519.Scalar) *curve25519.PublicKey[T] {
	out.ScalarBaseMult(sharedData)
	out.Add(out, spendPub)
	return out
}

func GetEphemeralPublicKey[T curve25519.PointOperations](out, spendPub, viewPub *curve25519.PublicKey[T], txKey *curve25519.Scalar, outputIndex uint64) *curve25519.PublicKey[T] {
	derivation := GetDerivation(new(curve25519.PublicKey[T]), viewPub, txKey)

	return GetPublicKeyForSharedData(out,
		spendPub,
		crypto.GetDerivationSharedDataForOutputIndex(new(curve25519.Scalar), derivation.Bytes(), outputIndex),
	)
}

func GetEphemeralPublicKeyWithViewKey[T curve25519.PointOperations](out, spendPub *curve25519.PublicKey[T], txPubKey *curve25519.PublicKey[T], viewKey *curve25519.Scalar, outputIndex uint64) *curve25519.PublicKey[T] {
	derivation := GetDerivation(out, txPubKey, viewKey)

	return GetPublicKeyForSharedData(out,
		spendPub,
		crypto.GetDerivationSharedDataForOutputIndex(new(curve25519.Scalar), derivation.Bytes(), outputIndex),
	)
}

func GetEphemeralPublicKeyAndViewTagWithViewKey[T curve25519.PointOperations](out, spendPub, txPubKey *curve25519.PublicKey[T], viewKey *curve25519.Scalar, outputIndex uint64) (*curve25519.PublicKey[T], uint8) {
	derivation := GetDerivation(new(curve25519.PublicKey[T]), txPubKey, viewKey)

	pK, viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndex(new(curve25519.Scalar), derivation.Bytes(), outputIndex)
	return GetPublicKeyForSharedData(out, spendPub, pK), viewTag
}

func CalculateTransactionOutput[T curve25519.PointOperations](a Interface, txKey *curve25519.Scalar, outputIndex, amount uint64) (out transaction.Output, additionalTxPub *curve25519.PublicKey[T], encryptedAmount uint64) {
	var pK curve25519.Scalar

	spendPub := curve25519.DecodeCompressedPoint(new(curve25519.PublicKey[T]), *a.SpendPublicKey())
	if sa, ok := a.(InterfaceSubaddress); ok && sa.IsSubaddress() {
		additionalTxPub = new(curve25519.PublicKey[T]).ScalarMult(txKey, spendPub)
	}

	derivation := GetDerivation(new(curve25519.PublicKey[T]), curve25519.DecodeCompressedPoint(new(curve25519.PublicKey[T]), *a.ViewPublicKey()), txKey)

	_, viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndex(&pK, derivation.Bytes(), outputIndex)

	out.Type = transaction.TxOutToTaggedKey
	out.Index = outputIndex
	out.ViewTag.Slice()[0] = viewTag
	out.EphemeralPublicKey = GetPublicKeyForSharedData(new(curve25519.PublicKey[T]), spendPub, &pK).Bytes()

	return out, additionalTxPub, ringct.DecryptOutputAmount(curve25519.PrivateKeyBytes(pK.Bytes()), amount)
}

func GetEphemeralPublicKeyAndViewTag[T curve25519.PointOperations](out, spendPub, viewPub *curve25519.PublicKey[T], txKey *curve25519.Scalar, outputIndex uint64) (*curve25519.PublicKey[T], uint8) {
	derivation := GetDerivation(new(curve25519.PublicKey[T]), viewPub, txKey)

	var pK curve25519.Scalar
	_, viewTag := crypto.GetDerivationSharedDataAndViewTagForOutputIndex(&pK, derivation.Bytes(), outputIndex)

	return GetPublicKeyForSharedData(out, spendPub, &pK), viewTag
}

func GetDerivation[T curve25519.PointOperations](out *curve25519.PublicKey[T], viewPub *curve25519.PublicKey[T], txKey *curve25519.Scalar) *curve25519.PublicKey[T] {
	out.ScalarMult(txKey, viewPub)
	out.MultByCofactor(out)
	return out
}

type SignatureVerifyResult int

const (
	ResultFailZeroSpend SignatureVerifyResult = -2
	ResultFailZeroView  SignatureVerifyResult = -1
)
const (
	ResultFail = SignatureVerifyResult(iota)
	ResultSuccessSpend
	ResultSuccessView
)

func GetMessageHash(a Interface, message []byte, mode uint8) types.Hash {
	return crypto.Keccak256Var(
		[]byte("MoneroMessageSignature\x00"),
		a.SpendPublicKey()[:],
		a.ViewPublicKey()[:],
		[]byte{mode},
		binary.AppendUvarint(nil, uint64(len(message))),
		message,
	)
}

func VerifyMessage(a Interface, message []byte, signature string) SignatureVerifyResult {
	var hash types.Hash

	if strings.HasPrefix(signature, "SigV1") {
		hash = crypto.Keccak256(message)
	} else if strings.HasPrefix(signature, "SigV2") {
		hash = GetMessageHash(a, message, 0)
	} else {
		return ResultFail
	}
	raw := base58.DecodeMoneroBase58([]byte(signature[5:]))

	sig := crypto.NewSignatureFromBytes[curve25519.VarTimeOperations](raw)

	if sig == nil {
		return ResultFail
	}

	var spendPub, viewPub curve25519.VarTimePublicKey
	curve25519.DecodeCompressedPoint(&spendPub, *a.SpendPublicKey())
	curve25519.DecodeCompressedPoint(&viewPub, *a.ViewPublicKey())

	if crypto.VerifyMessageSignature(hash, &spendPub, *sig) {
		return ResultSuccessSpend
	}

	// Special mode: view wallets in Monero GUI could generate signatures with spend public key proper, with message hash of spend wallet mode, but zero spend private key
	if crypto.VerifyMessageSignatureSplit(hash, &spendPub, zeroKeyPub, *sig) {
		return ResultFailZeroSpend
	}

	if strings.HasPrefix(signature, "SigV2") {
		hash = GetMessageHash(a, message, 1)
	}

	if crypto.VerifyMessageSignature(hash, &viewPub, *sig) {
		return ResultSuccessView
	}

	return ResultFail
}

// VerifyMessageFallbackToZero Check for Monero GUI behavior to generate wrong signatures on view-only wallets
func VerifyMessageFallbackToZero(a Interface, message []byte, signature string) SignatureVerifyResult {
	var hash types.Hash

	if strings.HasPrefix(signature, "SigV1") {
		hash = crypto.Keccak256(message)
	} else if strings.HasPrefix(signature, "SigV2") {
		hash = GetMessageHash(a, message, 0)
	} else {
		return ResultFail
	}
	raw := base58.DecodeMoneroBase58([]byte(signature[5:]))

	sig := crypto.NewSignatureFromBytes[curve25519.VarTimeOperations](raw)

	if sig == nil {
		return ResultFail
	}

	var spendPub, viewPub curve25519.VarTimePublicKey
	curve25519.DecodeCompressedPoint(&spendPub, *a.SpendPublicKey())
	curve25519.DecodeCompressedPoint(&viewPub, *a.ViewPublicKey())

	if crypto.VerifyMessageSignature(hash, &spendPub, *sig) {
		return ResultSuccessSpend
	}

	// Special mode: view wallets in Monero GUI could generate signatures with spend public key proper, with message hash of spend wallet mode, but zero spend private key
	if crypto.VerifyMessageSignatureSplit(hash, &spendPub, zeroKeyPub, *sig) {
		return ResultFailZeroSpend
	}

	if strings.HasPrefix(signature, "SigV2") {
		hash = GetMessageHash(a, message, 1)
	}

	if crypto.VerifyMessageSignature(hash, &viewPub, *sig) {
		return ResultSuccessView
	}

	// Special mode
	if crypto.VerifyMessageSignatureSplit(hash, &viewPub, zeroKeyPub, *sig) {
		return ResultFailZeroView
	}

	return ResultFail
}
