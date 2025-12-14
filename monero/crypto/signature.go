package crypto

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/go-hex"
)

// Signature Schnorr signature
type Signature[T curve25519.PointOperations] struct {
	// C hash of data in signature, also called e
	C curve25519.Scalar
	// R result of the signature, also called s
	R curve25519.Scalar
}

// SignatureSigningHandler receives k, inserts it or a pubkey into its data, and produces a []byte buffer for Signing/Verifying
type SignatureSigningHandler func(r *curve25519.Scalar) []byte

// SignatureVerificationHandler receives r = pubkey(k), inserts it into its data, and produces a []byte buffer for Signing/Verifying
type SignatureVerificationHandler[T curve25519.PointOperations] func(r *curve25519.PublicKey[T]) []byte

func NewSignatureFromBytes[T curve25519.PointOperations](buf []byte) *Signature[T] {
	if len(buf) != curve25519.PrivateKeySize*2 {
		return nil
	}
	signature := Signature[T]{}

	if _, err := signature.C.SetCanonicalBytes(buf[:curve25519.PrivateKeySize]); err != nil {
		return nil
	} else if _, err := signature.R.SetCanonicalBytes(buf[curve25519.PrivateKeySize:]); err != nil {
		return nil
	}

	return &signature
}

func (s Signature[T]) String() string {
	return hex.EncodeToString(s.Bytes())
}

func (s Signature[T]) Bytes() []byte {
	var buf [curve25519.PrivateKeySize * 2]byte
	copy(buf[:], s.C.Bytes())
	copy(buf[curve25519.PrivateKeySize:], s.R.Bytes())
	return buf[:]
}

// Verify checks a Schnorr Signature using H = keccak, base = G
func (s Signature[T]) Verify(handler SignatureVerificationHandler[T], publicKey *curve25519.PublicKey[T]) (ok bool) {
	return s.VerifyPrecomputed(handler, publicKey, GeneratorG)
}

// VerifyPrecomputed checks a Schnorr Signature using H = keccak, and specified base
func (s Signature[T]) VerifyPrecomputed(handler SignatureVerificationHandler[T], publicKey *curve25519.PublicKey[T], base *curve25519.Generator) (ok bool) {
	// is zero
	if s.C.Equal(new(curve25519.Scalar)) == 1 {
		return false
	}

	//s = C * k, R * G
	sp := new(curve25519.PublicKey[T]).DoubleScalarMultPrecomputedB(&s.C, publicKey, &s.R, base)
	if sp.P().Equal(infinityPoint) == 1 {
		return false
	}

	return s.C.Equal(ScalarDeriveLegacy(new(curve25519.Scalar), handler(sp))) == 1
}

// CreateSignature produces a Schnorr Signature using H = keccak
func CreateSignature[T curve25519.PointOperations](handler SignatureSigningHandler, privateKey *curve25519.Scalar, randomReader io.Reader) Signature[T] {
	var k, C curve25519.Scalar
	curve25519.RandomScalar(&k, randomReader)

	ScalarDeriveLegacy(&C, handler(&k))

	signature := Signature[T]{
		// e
		C: C,
		R: curve25519.Scalar{},
	}

	// s = k - x * e
	// EdDSA is an altered version, with addition instead of subtraction
	signature.R.Subtract(&k, new(curve25519.Scalar).Multiply(&signature.C, privateKey))
	return signature
}

func CreateMessageSignature[T curve25519.PointOperations](prefixHash types.Hash, key *curve25519.Scalar, randomReader io.Reader) Signature[T] {
	buf := &SignatureComm[T]{}
	buf.Hash = prefixHash
	buf.Key.ScalarBaseMult(key)

	return CreateSignature[T](func(k *curve25519.Scalar) []byte {
		buf.Comm.ScalarBaseMult(k)
		return buf.Bytes()
	}, key, randomReader)
}

func VerifyMessageSignature[T curve25519.PointOperations](prefixHash types.Hash, publicKey *curve25519.PublicKey[T], signature Signature[T]) bool {
	return VerifyMessageSignatureSplit(prefixHash, publicKey, publicKey, signature)
}

// VerifyMessageSignatureSplit Allows specifying a different signer key than for the rest. Use VerifyMessageSignature in all other cases
func VerifyMessageSignatureSplit[T curve25519.PointOperations](prefixHash types.Hash, commPublicKey, signPublicKey *curve25519.PublicKey[T], signature Signature[T]) bool {
	buf := &SignatureComm[T]{}
	buf.Hash = prefixHash
	buf.Key.P().Set(commPublicKey.P())

	return signature.Verify(func(r *curve25519.PublicKey[T]) []byte {
		buf.Comm.P().Set(r.P())
		return buf.Bytes()
	}, signPublicKey)
}
