package fcmp_plus_plus

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestSAL(t *testing.T) {
	rng := crypto.NewDeterministicTestGenerator()

	var x, y curve25519.Scalar
	curve25519.RandomScalar(&x, rng)
	curve25519.RandomScalar(&y, rng)

	var output Output[curve25519.ConstantTimeOperations]
	output.O.Add(new(curve25519.ConstantTimePublicKey).ScalarBaseMult(&x), new(curve25519.ConstantTimePublicKey).ScalarMultPrecomputed(&y, crypto.GeneratorT))
	curve25519.RandomPoint(&output.I, rng)
	curve25519.RandomPoint(&output.C, rng)

	var L curve25519.ConstantTimePublicKey
	L.ScalarMult(&x, &output.I)

	rerandomizedOutput := output.Rerandomize(rng)
	opening := rerandomizedOutput.OpenInput(&x, &y)
	L_, sal := opening.Prove(types.ZeroHash, rng)
	if L.Equal(&L_) == 0 {
		t.Fatalf("L does not equal L_ (%x != %x)", L.Bytes(), L_.Bytes())
	}
	var verifier BatchVerifier[curve25519.ConstantTimeOperations]
	sal.Verify(&verifier, types.ZeroHash, &rerandomizedOutput.Input, &L, rng)
	if !verifier.Verify() {
		t.Fatalf("batch verifier does not verify")
	}
}
