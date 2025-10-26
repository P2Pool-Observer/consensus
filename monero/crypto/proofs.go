package crypto

import (
	"crypto/rand"
	"errors"
	"strings"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
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
	Signature    Signature[T]
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
		output = append(output, string(base58.EncodeMoneroBase58(claim.SharedSecret.Slice())))
		output = append(output, string(base58.EncodeMoneroBase58(claim.Signature.Bytes())))
	}
	return strings.Join(output, "")
}

func (p TxProof[T]) Verify(prefixHash types.Hash, A, B *curve25519.PublicKey[T], txPubs ...curve25519.PublicKey[T]) (index int, ok bool) {
	for i, pub := range txPubs {
		if len(p.Claims) <= i {
			return
		}
		if VerifyTxProof(prefixHash, &pub, A, B, &p.Claims[i].SharedSecret, p.Claims[i].Signature, p.Version) {
			return i, true
		}
	}
	return -1, false
}

func NewTxProofFromSharedSecretSignaturePairs[T curve25519.PointOperations](t TxProofType, version uint8, sharedSecrets []curve25519.PublicKey[T], signatures []Signature[T]) TxProof[T] {
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
var encodedB58SignatureSize = len(base58.EncodeMoneroBase58((&Signature[curve25519.ConstantTimeOperations]{}).Bytes()))

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

	if str[offset+1] != 'V' {
		return TxProof[T]{}, errors.New("invalid tx proof")
	}

	switch str[offset+2] {
	case '1':
		proof.Version = 1
	case '2':
		proof.Version = 2
	default:
		return TxProof[T]{}, errors.New("invalid tx proof: unknown version")
	}

	offset += 2

	recordSize := encodedB58SecretSize + encodedB58SignatureSize

	if len(str)-offset == 0 || (len(str)-offset)-offset%recordSize != 0 {
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
		if curve25519.DecodeCompressedPoint(&sharedSecret, curve25519.PublicKeyBytes(sharedSecretBuf)) == nil {
			return TxProof[T]{}, errors.New("invalid tx proof: invalid shared secret")
		}

		signatureBuf := base58.DecodeMoneroBase58([]byte(str[i+encodedB58SecretSize : i+encodedB58SecretSize+encodedB58SignatureSize]))
		if signatureBuf == nil {
			return TxProof[T]{}, errors.New("invalid tx proof: invalid signature encoding")
		}

		signature := NewSignatureFromBytes[T](signatureBuf)
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

var TxProofV2DomainSeparatorHash = Keccak256([]byte("TXPROOF_V2")) // HASH_KEY_TXPROOF_V2

func GenerateTxProofV2[T curve25519.PointOperations](prefixHash types.Hash, R, A, B, D *curve25519.PublicKey[T], r *curve25519.Scalar) (signature Signature[T]) {
	comm := &SignatureComm_2[T]{}
	comm.Message = prefixHash

	//shared secret
	comm.D = *D

	comm.Separator = TxProofV2DomainSeparatorHash
	comm.R = *R
	comm.A = *A

	signature = CreateSignature[T](func(k *edwards25519.Scalar) []byte {
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

		return comm.Bytes()
	}, r, rand.Reader)

	return signature
}

func GenerateTxProofV1[T curve25519.PointOperations](prefixHash types.Hash, A, B, D *curve25519.PublicKey[T], r *curve25519.Scalar) (signature Signature[T]) {
	comm := &SignatureComm_2_V1[T]{}
	comm.Message = prefixHash

	//shared secret
	comm.D = *D

	signature = CreateSignature[T](func(k *edwards25519.Scalar) []byte {
		if B == nil {
			// compute X = k*G
			comm.X.ScalarBaseMult(k)
		} else {
			// compute X = k*B
			comm.X.ScalarMult(k, B)
		}

		comm.Y.ScalarMult(k, A)

		return comm.Bytes()
	}, r, rand.Reader)

	return signature
}

func VerifyTxProof[T curve25519.PointOperations](prefixHash types.Hash, R, A, B, D *curve25519.PublicKey[T], sig Signature[T], version uint8) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()

	if A == nil || D == nil || (version > 1 && R == nil) {
		return false
	}

	var cR curve25519.PublicKey[T]
	if version == 1 {
		// cR = sig.c*G
		cR.ScalarBaseMult(&sig.R)
	} else {
		// cR = sig.c*R
		cR.ScalarMult(&sig.R, R)
	}

	var X, tmp curve25519.PublicKey[T]

	if B != nil {
		// X = sig.c * R + sig.r * B
		X.Add(&cR, tmp.ScalarMult(&sig.R, B))
	} else {
		// X = sig.c * R + sig.r * G
		X.Add(&cR, tmp.ScalarBaseMult(&sig.R))
	}

	var cD, rA, Y curve25519.PublicKey[T]

	// cD = sig.c*D
	cD.ScalarMult(&sig.C, D)

	// rA = sig.r*A
	rA.ScalarMult(&sig.R, A)

	// Y = sig.c*D + sig.r*A
	Y.Add(&cD, &rA)

	// Compute hash challenge
	// for v1, c2 = Hs(Msg || D || X || Y)
	// for v2, c2 = Hs(Msg || D || X || Y || sep || R || A || B)

	var C curve25519.Scalar
	switch version {
	case 1:
		comm := SignatureComm_2_V1[T]{
			Message: prefixHash,
			D:       *D,
			X:       X,
			Y:       Y,
		}
		ScalarDeriveLegacyNoAllocate(&C, comm.Bytes())
	case 2:
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

		ScalarDeriveLegacyNoAllocate(&C, comm.Bytes())

	default:
		return false
	}

	// is zero, c2 == sig.c
	return new(curve25519.Scalar).Subtract(&C, &sig.C).Equal(&curve25519.Scalar{}) == 0
}
