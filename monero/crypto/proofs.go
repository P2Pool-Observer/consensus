package crypto

import (
	"errors"
	"fmt"
	"strings"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
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

type TxProofClaim struct {
	SharedSecret PublicKey
	Signature    *Signature
}
type TxProof struct {
	Type    TxProofType
	Version uint8

	Claims []TxProofClaim
}

func (p TxProof) String() string {
	output := make([]string, 1, 1+len(p.Claims)*2)
	output[0] = fmt.Sprintf("%sV%d", p.Type, p.Version)

	for _, claim := range p.Claims {
		output = append(output, string(base58.EncodeMoneroBase58(claim.SharedSecret.AsSlice())))
		output = append(output, string(base58.EncodeMoneroBase58(claim.Signature.Bytes())))
	}
	return strings.Join(output, "")
}

func (p TxProof) Verify(prefixHash types.Hash, A, B PublicKey, txPubs ...PublicKey) (index int, ok bool) {
	for i, pub := range txPubs {
		if len(p.Claims) <= i {
			return
		}
		if VerifyTxProof(prefixHash, pub, A, B, p.Claims[i].SharedSecret, p.Claims[i].Signature, p.Version) {
			return i, true
		}
	}
	return -1, false
}

func NewTxProofFromSharedSecretSignaturePairs(t TxProofType, version uint8, sharedSecrets []PublicKey, signatures []*Signature) TxProof {
	proof := TxProof{
		Type:    t,
		Version: version,
		Claims:  make([]TxProofClaim, 0, len(sharedSecrets)),
	}

	if len(sharedSecrets) != len(signatures) {
		return TxProof{}
	}

	for i := range sharedSecrets {
		proof.Claims = append(proof.Claims, TxProofClaim{
			SharedSecret: sharedSecrets[i],
			Signature:    signatures[i],
		})
	}
	return proof
}

var encodedB58SecretSize = len(base58.EncodeMoneroBase58(ZeroPrivateKeyBytes[:]))
var encodedB58SignatureSize = len(base58.EncodeMoneroBase58((&Signature{edwards25519.NewScalar(), edwards25519.NewScalar()}).Bytes()))

func NewTxProofFromString(str string) (TxProof, error) {
	proof := TxProof{}

	if strings.HasPrefix(str, string(InProof)) {
		proof.Type = InProof
	} else if strings.HasPrefix(str, string(OutProof)) {
		proof.Type = OutProof
	} else {
		return TxProof{}, errors.New("invalid tx proof: unknown prefix")
	}

	offset := len(proof.Type)

	if len(str) <= offset+2 {
		return TxProof{}, errors.New("invalid tx proof")
	}

	if str[offset+1] != 'V' {
		return TxProof{}, errors.New("invalid tx proof")
	}

	switch str[offset+2] {
	case '1':
		proof.Version = 1
	case '2':
		proof.Version = 2
	default:
		return TxProof{}, errors.New("invalid tx proof: unknown version")
	}

	offset += 2

	recordSize := encodedB58SecretSize + encodedB58SignatureSize

	if len(str)-offset == 0 || (len(str)-offset)-offset%recordSize != 0 {
		return TxProof{}, errors.New("invalid tx proof: wrong length")
	}

	numSigs := (len(str) - offset) / recordSize

	proof.Claims = make([]TxProofClaim, 0, numSigs)
	for i := offset; i < len(str); i += recordSize {
		sharedSecretBuf := base58.DecodeMoneroBase58([]byte(str[i : i+encodedB58SecretSize]))
		if sharedSecretBuf == nil {
			return TxProof{}, errors.New("invalid tx proof: invalid shared secret encoding")
		}
		sharedSecret := PublicKeyBytes(sharedSecretBuf)
		if sharedSecret.AsPoint() == nil {
			return TxProof{}, errors.New("invalid tx proof: invalid shared secret")
		}

		signatureBuf := base58.DecodeMoneroBase58([]byte(str[i+encodedB58SecretSize : i+encodedB58SecretSize+encodedB58SignatureSize]))
		if signatureBuf == nil {
			return TxProof{}, errors.New("invalid tx proof: invalid signature encoding")
		}

		signature := NewSignatureFromBytes(signatureBuf)
		if signature == nil {
			return TxProof{}, errors.New("invalid tx proof: invalid signature")
		}

		proof.Claims = append(proof.Claims, TxProofClaim{
			SharedSecret: &sharedSecret,
			Signature:    signature,
		})
	}
	return proof, nil
}

var TxProofV2DomainSeparatorHash = Keccak256([]byte("TXPROOF_V2")) // HASH_KEY_TXPROOF_V2

func GenerateTxProofV2(prefixHash types.Hash, R, A, B, D PublicKey, r PrivateKey) (signature *Signature) {
	comm := &SignatureComm_2{}
	comm.Message = prefixHash

	//shared secret
	comm.D = D

	comm.Separator = TxProofV2DomainSeparatorHash
	comm.R = R
	comm.A = A

	signature = CreateSignature(func(k PrivateKey) []byte {
		if B == nil {
			// compute X = k*G
			comm.X = k.PublicKey()
			comm.B = nil
		} else {
			// compute X = k*B
			comm.X = k.GetDerivation(B)
			comm.B = B
		}

		comm.Y = k.GetDerivation(A)

		return comm.Bytes()
	}, r)

	return signature
}

func GenerateTxProofV1(prefixHash types.Hash, A, B, D PublicKey, r PrivateKey) (signature *Signature) {
	comm := &SignatureComm_2_V1{}
	comm.Message = prefixHash

	//shared secret
	comm.D = D

	signature = CreateSignature(func(k PrivateKey) []byte {
		if B == nil {
			// compute X = k*G
			comm.X = k.PublicKey()
		} else {
			// compute X = k*B
			comm.X = k.GetDerivation(B)
		}

		comm.Y = k.GetDerivation(A)

		return comm.Bytes()
	}, r)

	return signature
}

func VerifyTxProof(prefixHash types.Hash, R, A, B, D PublicKey, sig *Signature, version uint8) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()

	if sig == nil || A == nil || D == nil || (version > 1 && R == nil) {
		return false
	}

	var cR PublicKey
	if version == 1 {
		// cR = sig.c*G
		cR = PrivateKeyFromScalar(sig.R).PublicKey()
	} else {
		// cR = sig.c*R
		cR = PrivateKeyFromScalar(sig.R).GetDerivation(R)
	}

	var X *PublicKeyPoint
	if B != nil {
		// X = sig.c * R + sig.r * B
		X = cR.AsPoint().Add(PrivateKeyFromScalar(sig.R).GetDerivation(B).AsPoint())
	} else {
		// X = sig.c * R + sig.r * G
		X = cR.AsPoint().Add(PrivateKeyFromScalar(sig.R).PublicKey().AsPoint())
	}

	// cD = sig.c*D
	cD := PrivateKeyFromScalar(sig.C).GetDerivation(D)

	// rA = sig.r*A
	rA := PrivateKeyFromScalar(sig.R).GetDerivation(A)

	// Y = sig.c*D + sig.r*A
	Y := cD.AsPoint().Add(rA.AsPoint())

	// Compute hash challenge
	// for v1, c2 = Hs(Msg || D || X || Y)
	// for v2, c2 = Hs(Msg || D || X || Y || sep || R || A || B)

	var C *edwards25519.Scalar
	switch version {
	case 1:
		comm := SignatureComm_2_V1{
			Message: prefixHash,
			D:       D,
			X:       X,
			Y:       Y,
		}

		C = ScalarDeriveLegacy(comm.Bytes())
	case 2:
		comm := SignatureComm_2{
			Message:   prefixHash,
			D:         D,
			R:         R,
			A:         A,
			B:         B,
			Separator: TxProofV2DomainSeparatorHash,
			X:         X,
			Y:         Y,
		}

		C = ScalarDeriveLegacy(comm.Bytes())

	default:
		return false
	}

	// is zero, c2 == sig.c
	return PrivateKeyFromScalar(C).Subtract(PrivateKeyFromScalar(sig.C)).AsScalar().Scalar().Equal(&edwards25519.Scalar{}) == 0
}
