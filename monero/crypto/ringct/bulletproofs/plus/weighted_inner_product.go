package plus

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type WeightedInnerProductProof[T curve25519.PointOperations] struct {
	L           []curve25519.PublicKey[T]
	R           []curve25519.PublicKey[T]
	A           curve25519.PublicKey[T]
	B           curve25519.PublicKey[T]
	RAnswer     curve25519.Scalar
	SAnswer     curve25519.Scalar
	DeltaAnswer curve25519.Scalar
}

func (wipp WeightedInnerProductProof[T]) BufferLength(signature bool) (n int) {
	if !signature {
		n += utils.UVarInt64Size(len(wipp.L)) + utils.UVarInt64Size(len(wipp.R))
	}
	return n + curve25519.PublicKeySize*2 + curve25519.PublicKeySize*len(wipp.L) + curve25519.PublicKeySize*len(wipp.R) + curve25519.PrivateKeySize*3
}

type WeightedInnerProductStatement[T curve25519.PointOperations] struct {
	P curve25519.PublicKey[T]
	Y bulletproofs.ScalarVector[T]
}

func NewWeightedInnerProductStatement[T curve25519.PointOperations](P *curve25519.PublicKey[T], y *curve25519.Scalar, n int) WeightedInnerProductStatement[T] {
	if bulletproofs.PaddedPowerOfTwo(n) != n {
		panic("n must be power of two")
	}

	// y ** n
	yVec := make(bulletproofs.ScalarVector[T], n)
	yVec[0] = *y
	for i := 1; i < n; i++ {
		yVec[i] = *new(curve25519.Scalar).Multiply(&yVec[i-1], y)
	}

	return WeightedInnerProductStatement[T]{
		P: *P,
		Y: yVec,
	}
}

func (wips WeightedInnerProductStatement[T]) Verify(verifier *BatchVerifier[T], transcript *curve25519.Scalar, proof WeightedInnerProductProof[T], randomReader io.Reader) bool {
	panic("todo")
}
