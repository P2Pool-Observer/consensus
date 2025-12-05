package carrot

import (
	"errors"
	"io"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

// PQTurnstile Implements Post-quantum Turnstile Design for Carrot/FCMP++ Enotes
//
// See https://gist.github.com/jeffro256/146bfd5306ea3a8a2a0ea4d660cd2243
type PQTurnstile[T curve25519.PointOperations] struct {
	FetchOutput     func(id types.Hash, outputIndex int) (pub curve25519.PublicKeyBytes, commitment curve25519.PublicKeyBytes, err error)
	IsKeyImageSpent func(ki curve25519.PublicKeyBytes) bool
}

var ErrTorsionedPoint = errors.New("torsioned point is not allowed")
var ErrFailedAmountCommitment = errors.New("failed recomputing amount commitment")
var ErrFailedOutputPub = errors.New("failed recomputing output pubkey")
var ErrFailedSignature = errors.New("failed validation of partial spend pubkey signature")
var ErrKeyImageSpent = errors.New("key image already spent")

func (pqt PQTurnstile[T]) VerifyCoinbase(
	txId types.Hash, outputIndex int,
	partialSpendPub *curve25519.PublicKey[T],
	generateImagePreimage types.Hash,
	senderReceiverSecret types.Hash,
	amount uint64,
	migrationTxSignableHash types.Hash,
	sig crypto.Signature[T],
) error {

	// step 1
	outputPubBytes, amountCommitmentBytes, err := pqt.FetchOutput(txId, outputIndex)
	if err != nil {
		return err
	}

	var outputPub, amountCommitment curve25519.PublicKey[T]
	if _, err = outputPub.SetBytes(outputPubBytes[:]); err != nil {
		return err
	}
	if _, err = amountCommitment.SetBytes(amountCommitmentBytes[:]); err != nil {
		return err
	}

	// step 2
	if !outputPub.IsTorsionFree() || !amountCommitment.IsTorsionFree() || !partialSpendPub.IsTorsionFree() {
		return ErrTorsionedPoint
	}

	var hasher blake2b.Digest

	// step 3
	var generateImageKey curve25519.Scalar
	MakeGenerateImageKey(&hasher, &generateImageKey, partialSpendPub.AsBytes(), generateImagePreimage)

	// step 4
	var accountSpendPub curve25519.PublicKey[T]
	MakeSpendPubFromPartialSpendPub(&accountSpendPub, &generateImageKey, partialSpendPub)

	// step 5
	var amountCommitmentCheck curve25519.PublicKey[T]
	ringct.CalculateCommitmentCoinbase(&amountCommitmentCheck, amount)

	// step 6
	if amountCommitmentCheck.AsBytes() != amountCommitmentBytes {
		return ErrFailedAmountCommitment
	}

	// step 7-9
	outputPubkeyCheck := makeOneTimeAddressCoinbase(&hasher, senderReceiverSecret, amount, &accountSpendPub)

	// step 10
	if outputPubkeyCheck != outputPubBytes {
		return ErrFailedOutputPub
	}

	// step 11
	if !CheckSignatureT(migrationTxSignableHash, partialSpendPub, sig) {
		return ErrFailedSignature
	}

	// step 12
	var senderExtensionG curve25519.Scalar
	makeCarrotSenderExtensionGCoinbase(&hasher, &senderExtensionG, senderReceiverSecret, amount, accountSpendPub.AsBytes())

	var outputPubPrivate curve25519.Scalar
	outputPubPrivate.Add(&generateImageKey, &senderExtensionG)

	var ki curve25519.PublicKey[T]
	crypto.GetKeyImage(&ki, &crypto.KeyPair[T]{PublicKey: outputPub, PrivateKey: outputPubPrivate})

	// step 13
	if pqt.IsKeyImageSpent(ki.AsBytes()) {
		return ErrKeyImageSpent
	}

	return nil
}

func (pqt PQTurnstile[T]) Verify(
	txId types.Hash, outputIndex int,
	partialSpendPub *curve25519.PublicKey[T],
	generateImagePreimage types.Hash,
	isSubaddress bool,
	addressIndexPreimage2 types.Hash,
	senderReceiverSecret types.Hash,
	amount uint64,
	enoteType EnoteType,
	migrationTxSignableHash types.Hash,
	sig crypto.Signature[T],
) error {

	// step 1
	outputPubBytes, amountCommitmentBytes, err := pqt.FetchOutput(txId, outputIndex)
	if err != nil {
		return err
	}

	var outputPub, amountCommitment curve25519.PublicKey[T]
	if _, err = outputPub.SetBytes(outputPubBytes[:]); err != nil {
		return err
	}
	if _, err = amountCommitment.SetBytes(amountCommitmentBytes[:]); err != nil {
		return err
	}

	// step 2
	if !outputPub.IsTorsionFree() || !amountCommitment.IsTorsionFree() || !partialSpendPub.IsTorsionFree() {
		return ErrTorsionedPoint
	}

	var hasher blake2b.Digest

	// step 3
	var generateImageKey curve25519.Scalar
	MakeGenerateImageKey(&hasher, &generateImageKey, partialSpendPub.AsBytes(), generateImagePreimage)

	// step 4
	var accountSpendPub curve25519.PublicKey[T]
	MakeSpendPubFromPartialSpendPub(&accountSpendPub, &generateImageKey, partialSpendPub)

	// step 5
	var subaddressScalar curve25519.Scalar
	if isSubaddress {
		MakeSubaddressScalar(&hasher, &subaddressScalar, addressIndexPreimage2, accountSpendPub.AsBytes())
	} else {
		_, _ = subaddressScalar.SetCanonicalBytes((&curve25519.PrivateKeyBytes{1})[:])
	}

	// step 6
	var addressSpendPub curve25519.PublicKey[T]
	addressSpendPub.ScalarMult(&subaddressScalar, &accountSpendPub)

	// step 7
	var amountBlindingFactor curve25519.Scalar
	makeAmountBlindingFactor(&hasher, &amountBlindingFactor, senderReceiverSecret, amount, addressSpendPub.AsBytes(), enoteType)

	// step 8
	var amountCommitmentCheck curve25519.PublicKey[T]
	ringct.CalculateCommitment(&amountCommitmentCheck, ringct.Commitment{Mask: amountBlindingFactor, Amount: amount})

	// step 9
	if amountCommitmentCheck.AsBytes() != amountCommitmentBytes {
		return ErrFailedAmountCommitment
	}

	// step 10-12
	outputPubkeyCheck := makeOneTimeAddress(&hasher, senderReceiverSecret, &addressSpendPub, amountCommitment.AsBytes())

	// step 13
	if outputPubkeyCheck != outputPubBytes {
		return ErrFailedOutputPub
	}

	// step 14
	if !CheckSignatureT(migrationTxSignableHash, partialSpendPub, sig) {
		return ErrFailedSignature
	}

	// step 15
	var senderExtensionG curve25519.Scalar
	makeCarrotSenderExtensionGCoinbase(&hasher, &senderExtensionG, senderReceiverSecret, amount, accountSpendPub.AsBytes())

	var outputPubPrivate curve25519.Scalar
	outputPubPrivate.Add(&generateImageKey, &senderExtensionG)

	var ki curve25519.PublicKey[T]
	crypto.GetKeyImage(&ki, &crypto.KeyPair[T]{PublicKey: outputPub, PrivateKey: outputPubPrivate})

	// step 16
	if pqt.IsKeyImageSpent(ki.AsBytes()) {
		return ErrKeyImageSpent
	}

	return nil
}

type s_comm_T struct {
	Hash types.Hash
	Key  curve25519.PublicKeyBytes
	Comm curve25519.PublicKeyBytes
}

func (comm s_comm_T) Bytes() []byte {
	buf := make([]byte, 0, types.HashSize+curve25519.PublicKeySize*2)
	buf = append(buf, comm.Hash[:]...)
	buf = append(buf, comm.Key[:]...)
	buf = append(buf, comm.Comm[:]...)
	return buf
}

func CheckSignatureT[T curve25519.PointOperations](prefixHash types.Hash, pub *curve25519.PublicKey[T], sig crypto.Signature[T]) bool {
	return sig.VerifyPrecomputed(func(r *curve25519.PublicKey[T]) []byte {
		var comm s_comm_T
		comm.Hash = prefixHash
		comm.Key = pub.AsBytes()
		comm.Comm = r.AsBytes()
		return comm.Bytes()
	}, pub, crypto.GeneratorT)
}

func CreateSignatureT[T curve25519.PointOperations](prefixHash types.Hash, privateKey *curve25519.Scalar, randomReader io.Reader) crypto.Signature[T] {
	return crypto.CreateSignature[T](func(r *curve25519.Scalar) []byte {
		var comm s_comm_T
		comm.Hash = prefixHash
		comm.Key = new(curve25519.PublicKey[T]).ScalarMultPrecomputed(privateKey, crypto.GeneratorT).AsBytes()
		comm.Comm = new(curve25519.PublicKey[T]).ScalarMultPrecomputed(r, crypto.GeneratorT).AsBytes()
		return comm.Bytes()
	}, privateKey, randomReader)
}
