package ringct

import (
	"crypto/subtle"
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

type LazyCommitment struct {
	Mask   curve25519.Scalar
	Amount uint64
}

type CommitmentEncryptedAmount struct {
	EncryptedAmount

	Commitment curve25519.PublicKeyBytes
}

// ZeroCommitment A commitment to zero, defined with a mask of 1 (as to not be the identity).
var ZeroCommitment = LazyCommitment{
	Mask:   *(&curve25519.PrivateKeyBytes{1}).Scalar(),
	Amount: 0,
}

func CalculateFeeCommitment[T curve25519.PointOperations](out *curve25519.PublicKey[T], fee uint64) *curve25519.PublicKey[T] {
	return out.ScalarMultPrecomputed(AmountToScalar(new(curve25519.Scalar), fee), crypto.GeneratorH)
}

func CalculateCommitment[T curve25519.PointOperations](out *curve25519.PublicKey[T], c LazyCommitment) *curve25519.PublicKey[T] {
	Commit(out, c.Amount, &c.Mask)
	return out
}

var commitmentMaskKey = []byte("commitment_mask")

// CalculateCommitmentMask Equivalent to rct::genCommitmentMask
func CalculateCommitmentMask(out *curve25519.Scalar, k curve25519.PrivateKeyBytes) *curve25519.Scalar {
	return crypto.ScalarDeriveLegacy(out, commitmentMaskKey[:], k[:])
}

var encryptedAmountKey = []byte("amount")

// CalculateAmountEncodingFactor Equivalent to rct::genAmountEncodingFactor
func CalculateAmountEncodingFactor(k curve25519.PrivateKeyBytes) curve25519.PrivateKeyBytes {
	var key curve25519.PrivateKeyBytes
	h := crypto.NewKeccak256()
	_, _ = h.Write(encryptedAmountKey)
	_, _ = h.Write(k[:])
	_, _ = h.Read(key[:])
	return key
}

func AmountToScalar(out *curve25519.Scalar, amount uint64) *curve25519.Scalar {
	// no reduction is necessary: amountBytes is always lesser than l
	var amountBytes curve25519.PrivateKeyBytes
	binary.LittleEndian.PutUint64(amountBytes[:], amount)
	_, _ = out.SetCanonicalBytes(amountBytes[:])
	return out
}

type EncryptedAmount struct {
	// Mask used with a mask derived from the shared secret to encrypt the amount.
	Mask curve25519.PrivateKeyBytes `json:"mask"`

	// Amount The amount, as a scalar, encrypted.
	Amount curve25519.PrivateKeyBytes `json:"amount"`
}

func (a *EncryptedAmount) Encode(sharedSecret curve25519.PrivateKeyBytes, amount uint64, compactAmount bool) {
	clear(a.Amount.Slice())
	binary.LittleEndian.PutUint64(a.Amount.Slice(), amount)

	if compactAmount {
		// zero
		a.Mask = curve25519.ZeroPrivateKeyBytes

		key := CalculateAmountEncodingFactor(sharedSecret)
		subtle.XORBytes(a.Amount.Slice(), a.Amount.Slice(), key[:])
	} else {
		var sharedSecret1, sharedSecret2 curve25519.Scalar
		crypto.ScalarDeriveLegacy(&sharedSecret1, sharedSecret[:])
		crypto.ScalarDeriveLegacy(&sharedSecret2, sharedSecret1.Bytes())

		copy(a.Mask[:], sharedSecret1.Add(a.Mask.Scalar(), &sharedSecret1).Bytes())
		copy(a.Amount.Slice(), sharedSecret2.Add(a.Amount.Scalar(), &sharedSecret2).Bytes())
	}
}

func (a *EncryptedAmount) Decode(sharedSecret curve25519.PrivateKeyBytes, compactAmount bool) LazyCommitment {
	if compactAmount {
		var mask curve25519.Scalar
		CalculateCommitmentMask(&mask, sharedSecret)
		copy(a.Mask[:], mask.Bytes())

		key := CalculateAmountEncodingFactor(sharedSecret)
		subtle.XORBytes(a.Amount.Slice(), a.Amount.Slice(), key[:])

		return LazyCommitment{
			Mask:   mask,
			Amount: binary.LittleEndian.Uint64(a.Amount.Slice()),
		}
	} else {
		var sharedSecret1, sharedSecret2 curve25519.Scalar
		crypto.ScalarDeriveLegacy(&sharedSecret1, sharedSecret[:])
		crypto.ScalarDeriveLegacy(&sharedSecret2, sharedSecret1.Bytes())

		copy(a.Mask[:], sharedSecret1.Subtract(a.Mask.Scalar(), &sharedSecret1).Bytes())
		copy(a.Amount.Slice(), sharedSecret2.Subtract(a.Amount.Scalar(), &sharedSecret2).Bytes())

		return LazyCommitment{
			Mask:   sharedSecret1,
			Amount: binary.LittleEndian.Uint64(a.Amount.Slice()),
		}
	}
}

// CoinbaseAmountBlindingFactor precompute coinbase blinding factor scalar multiplication
var CoinbaseAmountBlindingFactor = (&curve25519.PrivateKeyBytes{1}).Scalar()
var coinbaseAmountBlindingFactorPub = new(curve25519.Point).ScalarBaseMult(CoinbaseAmountBlindingFactor)

// CalculateCommitmentCoinbase Specialized implementation with baked in blinding factor
// this is faster than CalculateCommitment, but is specific only for coinbase (as it uses a fixed amount blinding key)
func CalculateCommitmentCoinbase[T curve25519.PointOperations](out *curve25519.PublicKey[T], amount uint64) *curve25519.PublicKey[T] {
	var amountK curve25519.Scalar
	out.ScalarMultPrecomputed(AmountToScalar(&amountK, amount), crypto.GeneratorH)
	return out.Add(out, curve25519.FromPoint[T](coinbaseAmountBlindingFactorPub))
}

// Commit generates C =aG + bH from b, a is mask
func Commit[T curve25519.PointOperations](dst *curve25519.PublicKey[T], amount uint64, mask *curve25519.Scalar) {

	var amountK curve25519.Scalar
	dst.DoubleScalarBaseMultPrecomputed(AmountToScalar(&amountK, amount), crypto.GeneratorH, mask)
}
