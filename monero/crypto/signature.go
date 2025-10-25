package crypto

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

// Signature Schnorr signature
type Signature struct {
	// C hash of data in signature, also called e
	C edwards25519.Scalar
	// R result of the signature, also called s
	R edwards25519.Scalar
}

// SignatureSigningHandler receives k, inserts it or a pubkey into its data, and produces a []byte buffer for Signing/Verifying
type SignatureSigningHandler func(r *edwards25519.Scalar) []byte

// SignatureVerificationHandler receives r = pubkey(k), inserts it into its data, and produces a []byte buffer for Signing/Verifying
type SignatureVerificationHandler func(r *edwards25519.Point) []byte

func NewSignatureFromBytes(buf []byte) *Signature {
	if len(buf) != PrivateKeySize*2 {
		return nil
	}
	signature := Signature{}

	if _, err := signature.C.SetCanonicalBytes(buf[:PrivateKeySize]); err != nil {
		return nil
	} else if _, err := signature.R.SetCanonicalBytes(buf[PrivateKeySize:]); err != nil {
		return nil
	}

	return &signature
}

func (s Signature) Bytes() []byte {
	var buf [PrivateKeySize * 2]byte
	copy(buf[:], s.C.Bytes())
	copy(buf[PrivateKeySize:], s.R.Bytes())
	return buf[:]
}

// Verify checks a Schnorr Signature using H = keccak
func (s Signature) Verify(handler SignatureVerificationHandler, publicKey *edwards25519.Point) (ok bool, r *edwards25519.Point) {
	//s = C * k, R * G
	sp := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(&s.C, publicKey, &s.R)
	if sp.Equal(infinityPoint) == 1 {
		return false, nil
	}

	return s.C.Equal(ScalarDeriveLegacy(handler(sp))) == 1, sp
}

// CreateSignature produces a Schnorr Signature using H = keccak
func CreateSignature(handler SignatureSigningHandler, privateKey *edwards25519.Scalar, randomReader io.Reader) Signature {
	var k, C edwards25519.Scalar
	RandomScalar(&k, randomReader)

	ScalarDeriveLegacyNoAllocate(&C, handler(&k))

	signature := Signature{
		// e
		C: C,
		R: edwards25519.Scalar{},
	}

	// s = k - x * e
	// EdDSA is an altered version, with addition instead of subtraction
	signature.R.Subtract(&k, new(edwards25519.Scalar).Multiply(&signature.C, privateKey))
	return signature
}

func CreateMessageSignature(prefixHash types.Hash, key *PrivateKeyScalar, randomReader io.Reader) Signature {
	buf := &SignatureComm{}
	buf.Hash = prefixHash
	buf.Key.Point().UnsafeVarTimeScalarBaseMult(key.Scalar())

	return CreateSignature(func(k *edwards25519.Scalar) []byte {
		buf.Comm.Point().UnsafeVarTimeScalarBaseMult(k)
		return buf.Bytes()
	}, key.Scalar(), randomReader)
}

func VerifyMessageSignature(prefixHash types.Hash, publicKey *PublicKeyPoint, signature Signature) bool {
	return VerifyMessageSignatureSplit(prefixHash, publicKey, publicKey, signature)
}

// VerifyMessageSignatureSplit Allows specifying a different signer key than for the rest. Use VerifyMessageSignature in all other cases
func VerifyMessageSignatureSplit(prefixHash types.Hash, commPublicKey, signPublicKey *PublicKeyPoint, signature Signature) bool {
	buf := &SignatureComm{}
	buf.Hash = prefixHash
	buf.Key.Point().Set(commPublicKey.Point())

	ok, _ := signature.Verify(func(r *edwards25519.Point) []byte {
		buf.Comm.Point().Set(r)
		return buf.Bytes()
	}, signPublicKey.Point())
	return ok
}
