package proofs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	base58 "git.gammaspectra.live/P2Pool/monero-base58"
)

/*
OutProof = txPub, viewPub, nil, sharedSecret
InProof = viewPub, txPub, spendPub, sharedSecret
*/

type TxProofType string

const (
	OutProof TxProofType = "OutProof"
	InProof  TxProofType = "InProof"
)

type TxProofClaim[T curve25519.PointOperations] struct {
	SharedSecret curve25519.PublicKey[T]
	Signature    crypto.Signature[T]
}
type TxProof[T curve25519.PointOperations] struct {
	Type    TxProofType
	Version uint8

	Claims []TxProofClaim[T]
}

func (p TxProof[T]) String() string {
	output := make([]string, 1, 1+len(p.Claims)*2)
	output[0] = utils.SprintfNoEscape("%sV%d", p.Type, p.Version)

	for _, claim := range p.Claims {
		output = append(output, string(base58.EncodeMoneroBase58(claim.SharedSecret.Bytes())), string(base58.EncodeMoneroBase58(claim.Signature.Bytes())))
	}
	return strings.Join(output, "")
}

func (p TxProof[T]) Verify(prefixHash types.Hash, viewPub, spendPub *curve25519.PublicKey[T], txPubs ...curve25519.PublicKey[T]) (index int, ok bool) {
	if p.Type == OutProof {
		for i, pub := range txPubs {
			if len(p.Claims) <= i {
				return
			}
			if VerifyTxProof(prefixHash, &pub, viewPub, spendPub, &p.Claims[i].SharedSecret, p.Claims[i].Signature, p.Version) {
				return i, true
			}
		}
	} else if p.Type == InProof {
		for i, pub := range txPubs {
			if len(p.Claims) <= i {
				return
			}
			if VerifyTxProof(prefixHash, viewPub, &pub, spendPub, &p.Claims[i].SharedSecret, p.Claims[i].Signature, p.Version) {
				return i, true
			}
		}
	} else {
		return -1, false
	}

	return -1, false
}

func NewTxProofFromSharedSecretSignaturePairs[T curve25519.PointOperations](t TxProofType, version uint8, sharedSecrets []curve25519.PublicKey[T], signatures []crypto.Signature[T]) TxProof[T] {
	proof := TxProof[T]{
		Type:    t,
		Version: version,
		Claims:  make([]TxProofClaim[T], 0, len(sharedSecrets)),
	}

	if len(sharedSecrets) != len(signatures) {
		return TxProof[T]{}
	}

	for i := range sharedSecrets {
		proof.Claims = append(proof.Claims, TxProofClaim[T]{
			SharedSecret: sharedSecrets[i],
			Signature:    signatures[i],
		})
	}
	return proof
}

var encodedB58SecretSize = len(base58.EncodeMoneroBase58(curve25519.ZeroPrivateKeyBytes[:]))
var encodedB58SignatureSize = len(base58.EncodeMoneroBase58((&crypto.Signature[curve25519.ConstantTimeOperations]{}).Bytes()))

func NewTxProofFromString[T curve25519.PointOperations](str string) (TxProof[T], error) {
	proof := TxProof[T]{}

	if strings.HasPrefix(str, string(InProof)) {
		proof.Type = InProof
	} else if strings.HasPrefix(str, string(OutProof)) {
		proof.Type = OutProof
	} else {
		return TxProof[T]{}, errors.New("invalid tx proof: unknown prefix")
	}

	offset := len(proof.Type)

	if len(str) <= offset+2 {
		return TxProof[T]{}, errors.New("invalid tx proof")
	}

	if str[offset] != 'V' {
		return TxProof[T]{}, errors.New("invalid tx proof")
	}

	switch str[offset+1] {
	case '1':
		proof.Version = 1
	case '2':
		proof.Version = 2
	default:
		return TxProof[T]{}, errors.New("invalid tx proof: unknown version")
	}

	offset += 2

	recordSize := encodedB58SecretSize + encodedB58SignatureSize

	if len(str)-offset == 0 || (len(str)-offset)%recordSize != 0 {
		return TxProof[T]{}, errors.New("invalid tx proof: wrong length")
	}

	numSigs := (len(str) - offset) / recordSize

	proof.Claims = make([]TxProofClaim[T], 0, numSigs)
	for i := offset; i < len(str); i += recordSize {
		sharedSecretBuf := base58.DecodeMoneroBase58([]byte(str[i : i+encodedB58SecretSize]))
		if sharedSecretBuf == nil {
			return TxProof[T]{}, errors.New("invalid tx proof: invalid shared secret encoding")
		}
		var sharedSecret curve25519.PublicKey[T]
		if _, err := sharedSecret.SetBytes(sharedSecretBuf); err != nil {
			return TxProof[T]{}, fmt.Errorf("invalid tx proof: invalid shared secret: %w", err)
		}

		signatureBuf := base58.DecodeMoneroBase58([]byte(str[i+encodedB58SecretSize : i+encodedB58SecretSize+encodedB58SignatureSize]))
		if signatureBuf == nil {
			return TxProof[T]{}, errors.New("invalid tx proof: invalid signature encoding")
		}

		signature := crypto.NewSignatureFromBytes[T](signatureBuf)
		if signature == nil {
			return TxProof[T]{}, errors.New("invalid tx proof: invalid signature")
		}

		proof.Claims = append(proof.Claims, TxProofClaim[T]{
			SharedSecret: sharedSecret,
			Signature:    *signature,
		})
	}
	return proof, nil
}

var TxProofV2DomainSeparatorHash = crypto.Keccak256([]byte("TXPROOF_V2")) // HASH_KEY_TXPROOF_V2

func GenerateTxProof[T curve25519.PointOperations](prefixHash types.Hash, R, A, B, D *curve25519.PublicKey[T], r *curve25519.Scalar, version uint8) (signature crypto.Signature[T]) {
	if version != 1 && version != 2 {
		panic("unsupported version")
	}

	comm := &SignatureComm_2[T]{}
	comm.Message = prefixHash

	//shared secret
	comm.D = *D

	comm.Separator = TxProofV2DomainSeparatorHash
	if R != nil {
		comm.R = *R
	}
	comm.A = *A

	signature = crypto.CreateSignature[T](func(k *curve25519.Scalar) []byte {
		if B == nil {
			// compute X = k*G
			comm.X.ScalarBaseMult(k)
			comm.B = nil
		} else {
			// compute X = k*B
			comm.X.ScalarMult(k, B)
			comm.B = B
		}

		comm.Y.ScalarMult(k, A)

		return comm.Bytes(version)
	}, r, rand.Reader)

	return signature
}

func VerifyTxProof[T curve25519.PointOperations](prefixHash types.Hash, R, A, B, D *curve25519.PublicKey[T], sig crypto.Signature[T], version uint8) (ok bool) {
	if version != 1 && version != 2 {
		return false
	}

	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()

	if A == nil || D == nil || (version > 1 && R == nil) {
		return false
	}

	var X, Y curve25519.PublicKey[T]
	if B != nil {
		// X = sig.c * R + sig.r * B
		X.DoubleScalarMult(&sig.C, R, &sig.R, B)
	} else {
		// X = sig.c*R + sig.r*G
		X.DoubleScalarBaseMult(&sig.C, R, &sig.R)
	}

	// Y = sig.c*D + sig.r*A
	Y.DoubleScalarMult(&sig.C, D, &sig.R, A)

	// Compute hash challenge
	// for v1, c2 = Hs(Msg || D || X || Y)
	// for v2, c2 = Hs(Msg || D || X || Y || sep || R || A || B)

	comm := SignatureComm_2[T]{
		Message:   prefixHash,
		D:         *D,
		R:         *R,
		A:         *A,
		B:         B,
		Separator: TxProofV2DomainSeparatorHash,
		X:         X,
		Y:         Y,
	}

	var C curve25519.Scalar

	crypto.ScalarDeriveLegacy(&C, comm.Bytes(version))

	// is zero, c2 == sig.c
	result := new(curve25519.Scalar).Subtract(&C, &sig.C)
	return result.Equal(&curve25519.Scalar{}) == 1
}
