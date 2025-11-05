package transaction

import (
	"errors"
	"fmt"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client/rpc/daemon"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type Proofs interface {
	Verify(prefixHash types.Hash, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) error
	ProofType() ProofType
}

type ProofType uint8

func (p ProofType) CompactAmount() bool {
	switch p {
	case MLSAGBulletproofCompactAmount, CLSAGBulletproof, CLSAGBulletproofPlus:
		return true
	default:
		return false
	}
}

func (p ProofType) Bulletproof() bool {
	switch p {
	case MLSAGBulletproof, MLSAGBulletproofCompactAmount, CLSAGBulletproof:
		return true
	default:
		return false
	}
}

func (p ProofType) BulletproofPlus() bool {
	switch p {
	case CLSAGBulletproofPlus:
		return true
	default:
		return false
	}
}

const (
	TraceableRingSignatures = ProofType(iota)

	// AggregateMLSAGBorromean One MLSAG for multiple inputs and Borromean range proofs.
	//
	// This aligns with RCTTypeFull.
	AggregateMLSAGBorromean

	// MLSAGBorromean One MLSAG for each input and a Borromean range proof.
	//
	// This aligns with RCTTypeSimple.
	MLSAGBorromean

	// MLSAGBulletproof One MLSAG for each input and a Bulletproof.
	//
	// This aligns with RCTTypeBulletproof.
	MLSAGBulletproof

	// MLSAGBulletproofCompactAmount One MLSAG for each input and a Bulletproof, yet using EncryptedAmount::Compact.
	//
	// This aligns with RCTTypeBulletproof2.
	MLSAGBulletproofCompactAmount

	// CLSAGBulletproof One CLSAG for each input and a Bulletproof.
	//
	// This aligns with RCTTypeCLSAG.
	CLSAGBulletproof

	// CLSAGBulletproofPlus One CLSAG for each input and a Bulletproof+.
	//
	// This aligns with RCTTypeBulletproofPlus.
	CLSAGBulletproofPlus
)

func GetTransactionInputsData(tx Transaction, f func(in ...daemon.GetOutsInput) ([]client.Output, error)) (rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey, err error) {
	var request []daemon.GetOutsInput
	for _, i := range tx.Inputs() {
		var prefix uint64
		for _, o := range i.Offsets {
			prefix += o
			request = append(request, daemon.GetOutsInput{
				Amount: i.Amount,
				Index:  prefix,
			})
		}
	}

	outs, err := f(request...)
	if err != nil {
		return nil, nil, err
	}

	offset := 0
	var image, key, mask curve25519.VarTimePublicKey
	for _, i := range tx.Inputs() {
		var ring ringct.CommitmentRing[curve25519.VarTimeOperations]
		for range i.Offsets {
			if _, err = key.SetBytes(outs[offset].Key[:]); err != nil {
				return nil, nil, err
			}
			if _, err = mask.SetBytes(outs[offset].Mask[:]); err != nil {
				return nil, nil, err
			}

			ring = append(ring, [2]curve25519.VarTimePublicKey{key, mask})

			offset++
		}
		rings = append(rings, ring)

		if _, err = image.SetBytes(i.KeyImage[:]); err != nil {
			return nil, nil, err
		}
		images = append(images, image)
	}

	return rings, images, nil
}

var ErrInvalidRingSignature = errors.New("invalid ring signature")

type RingSignatures []ringct.RingSignature[curve25519.VarTimeOperations]

func (rs *RingSignatures) ProofType() ProofType {
	return TraceableRingSignatures
}

func (rs *RingSignatures) Verify(prefixHash types.Hash, rings []ringct.CommitmentRing[curve25519.VarTimeOperations], images []curve25519.VarTimePublicKey) error {
	if len(rings) != len(*rs) || len(images) != len(*rs) {
		return fmt.Errorf("rings length mismatch")
	}
	for i, sig := range *rs {
		if len(sig) != len(rings[i]) {
			return fmt.Errorf("ring member length mismatch")
		}
		if !sig.Verify(prefixHash, rings[i].Ring(), &images[i]) {
			return ErrInvalidRingSignature
		}
	}
	return nil
}

func (rs *RingSignatures) BufferLength() int {
	n := 0
	for _, sig := range *rs {
		n += sig.BufferLength()
	}
	return n
}

func (rs *RingSignatures) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	buf := preAllocatedBuf

	for _, sig := range *rs {
		if buf, err = sig.AppendBinary(buf); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

func (rs *RingSignatures) FromReader(reader utils.ReaderAndByteReader, inputs Inputs, outputs Outputs) (err error) {
	for _, input := range inputs {
		var sig ringct.RingSignature[curve25519.VarTimeOperations]
		if err = sig.FromReader(reader, len(input.Offsets)); err != nil {
			return err
		}
		*rs = append(*rs, sig)
	}
	return nil
}
