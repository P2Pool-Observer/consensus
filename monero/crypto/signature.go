package crypto

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

// Signature Schnorr signature
type Signature struct {
	// C hash of data in signature, also called e
	C *edwards25519.Scalar
	// R result of the signature, also called s
	R *edwards25519.Scalar
}

// SignatureSigningHandler receives k, inserts it or a pubkey into its data, and produces a []byte buffer for Signing/Verifying
type SignatureSigningHandler func(r PrivateKey) []byte

// SignatureVerificationHandler receives r = pubkey(k), inserts it into its data, and produces a []byte buffer for Signing/Verifying
type SignatureVerificationHandler func(r PublicKey) []byte

func NewSignatureFromBytes(buf []byte) *Signature {
	if len(buf) != types.HashSize*2 {
		return nil
	}
	signature := &Signature{}
	var err error
	if signature.C, err = new(edwards25519.Scalar).SetCanonicalBytes(buf[:32]); err != nil {
		return nil
	} else if signature.R, err = new(edwards25519.Scalar).SetCanonicalBytes(buf[32:]); err != nil {
		return nil
	} else {
		return signature
	}
}

func (s *Signature) Bytes() []byte {
	var buf [PrivateKeySize * 2]byte
	copy(buf[:], s.C.Bytes())
	copy(buf[PrivateKeySize:], s.R.Bytes())
	return buf[:]
}

// Verify checks a Schnorr Signature using H = keccak
func (s *Signature) Verify(handler SignatureVerificationHandler, publicKey PublicKey) (ok bool, r *PublicKeyPoint) {
	if s == nil {
		return false, nil
	}
	//s = C * k, R * G
	sp := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(s.C, publicKey.AsPoint().Point(), s.R)
	if sp.Equal(infinityPoint) == 1 {
		return false, nil
	}
	r = PublicKeyFromPoint(sp)
	return s.C.Equal(ScalarDeriveLegacy(handler(r))) == 1, r
}

// CreateSignature produces a Schnorr Signature using H = keccak
func CreateSignature(handler SignatureSigningHandler, privateKey PrivateKey, randomReader io.Reader) *Signature {
	k := PrivateKeyFromScalar(RandomScalar(randomReader))

	signature := &Signature{
		// e
		C: ScalarDeriveLegacy(handler(k)),
		R: &edwards25519.Scalar{},
	}

	// s = k - x * e
	// EdDSA is an altered version, with addition instead of subtraction
	signature.R = signature.R.Subtract(k.Scalar(), new(edwards25519.Scalar).Multiply(signature.C, privateKey.AsScalar().Scalar()))
	return signature
}

func CreateMessageSignature(prefixHash types.Hash, key PrivateKey, randomReader io.Reader) *Signature {
	buf := &SignatureComm{}
	buf.Hash = prefixHash
	buf.Key = key.PublicKey()

	return CreateSignature(func(k PrivateKey) []byte {
		buf.Comm = k.PublicKey()
		return buf.Bytes()
	}, key, randomReader)
}

func VerifyMessageSignature(prefixHash types.Hash, publicKey PublicKey, signature *Signature) bool {
	return VerifyMessageSignatureSplit(prefixHash, publicKey, publicKey, signature)
}

// VerifyMessageSignatureSplit Allows specifying a different signer key than for the rest. Use VerifyMessageSignature in all other cases
func VerifyMessageSignatureSplit(prefixHash types.Hash, commPublicKey, signPublicKey PublicKey, signature *Signature) bool {
	buf := &SignatureComm{}
	buf.Hash = prefixHash
	buf.Key = commPublicKey

	ok, _ := signature.Verify(func(r PublicKey) []byte {
		buf.Comm = r
		return buf.Bytes()
	}, signPublicKey)
	return ok
}
