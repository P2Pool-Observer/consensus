package proofs

import (
	"errors"
	"io"
	"slices"
	"strings"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	base58 "git.gammaspectra.live/P2Pool/monero-base58"
)

const SpendProofPrefix = "SpendProof"

type SpendProof[T curve25519.PointOperations] struct {
	Version uint8

	Signatures []crypto.Signature[T]
}

func (p SpendProof[T]) String() string {
	output := make([]string, 1, 1+len(p.Signatures))
	output[0] = utils.SprintfNoEscape("%sV%d", SpendProofPrefix, p.Version)

	for _, sig := range p.Signatures {
		output = append(output, string(base58.EncodeMoneroBase58(sig.Bytes())))
	}
	return strings.Join(output, "")
}

func (p SpendProof[T]) Verify(prefixHash types.Hash, keyImages []curve25519.PublicKey[T], rings []ringct.Ring[T]) bool {
	if p.Version != 1 {
		return false
	}
	if len(keyImages) != len(rings) {
		return false
	}
	ring0Len := len(rings[0])

	if ring0Len == 0 {
		return false
	}

	for i := range rings[1:] {
		if ring0Len != len(rings[i+1]) {
			return false
		}
	}

	if len(p.Signatures) != len(rings)*ring0Len {
		return false
	}

	for i, image := range keyImages {
		rs := ringct.RingSignature[T](p.Signatures[i*ring0Len : (i+1)*ring0Len])

		if !rs.Verify(prefixHash, rings[i], &image) {
			return false
		}
	}

	return true
}

func NewSpendProofFromString[T curve25519.PointOperations](str string) (SpendProof[T], error) {
	proof := SpendProof[T]{}

	if !strings.HasPrefix(str, SpendProofPrefix) {
		return SpendProof[T]{}, errors.New("invalid spend proof: unknown prefix")
	}

	offset := len(SpendProofPrefix)

	if len(str) <= offset+2 {
		return SpendProof[T]{}, errors.New("invalid spend proof")
	}

	if str[offset] != 'V' {
		return SpendProof[T]{}, errors.New("invalid spend proof")
	}

	switch str[offset+1] {
	case '1':
		proof.Version = 1
	default:
		return SpendProof[T]{}, errors.New("invalid spend proof: unknown version")
	}

	offset += 2

	recordSize := encodedB58SignatureSize

	if len(str)-offset == 0 || (len(str)-offset)%recordSize != 0 {
		return SpendProof[T]{}, errors.New("invalid spend proof: wrong length")
	}

	numSigs := (len(str) - offset) / recordSize

	proof.Signatures = make([]crypto.Signature[T], 0, numSigs)
	for i := offset; i < len(str); i += recordSize {
		signatureBuf := base58.DecodeMoneroBase58([]byte(str[i : i+encodedB58SignatureSize]))
		if signatureBuf == nil {
			return SpendProof[T]{}, errors.New("invalid spend proof: invalid signature encoding")
		}

		signature := crypto.NewSignatureFromBytes[T](signatureBuf)
		if signature == nil {
			return SpendProof[T]{}, errors.New("invalid spend proof: invalid signature")
		}

		proof.Signatures = append(proof.Signatures, *signature)
	}
	return proof, nil
}

func NewSpendProofFromSignatures[T curve25519.PointOperations](version uint8, signatures []crypto.Signature[T]) SpendProof[T] {
	proof := SpendProof[T]{
		Version:    version,
		Signatures: slices.Clone(signatures),
	}
	return proof
}

func GetSpendProof[T curve25519.PointOperations](txId types.Hash, message string, version uint8, ephemeralKeyPairs []*crypto.KeyPair[T], rings []ringct.Ring[T], randomReader io.Reader) (SpendProof[T], error) {
	prefixHash := TxPrefixHash(txId, message)

	if len(ephemeralKeyPairs) != len(rings) || len(ephemeralKeyPairs) == 0 {
		return SpendProof[T]{}, errors.New("invalid ring count")
	}
	// this is checked later, it's fine
	signatures := make([]crypto.Signature[T], 0, len(rings)*len(rings[0]))

	var keyImage curve25519.PublicKey[T]
	for i, ring := range rings {
		if len(ring) != len(rings[0]) {
			return SpendProof[T]{}, errors.New("invalid ring member count")
		}
		keyPair := ephemeralKeyPairs[i]

		crypto.GetBiasedKeyImage(&keyImage, keyPair)
		var rs ringct.RingSignature[T]
		if !rs.Sign(prefixHash, ring, keyPair, randomReader) {
			return SpendProof[T]{}, errors.New("error signing")
		}

		signatures = append(signatures, rs...)
	}

	return NewSpendProofFromSignatures(version, signatures), nil
}
