package fcmp_plus_plus

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestSAL(t *testing.T) {
	rng := crypto.NewDeterministicTestGenerator()

	var x, y curve25519.Scalar
	curve25519.RandomScalar(&x, rng)
	curve25519.RandomScalar(&y, rng)

	var O, I, C, L curve25519.ConstantTimePublicKey
	O.Add(new(curve25519.ConstantTimePublicKey).ScalarBaseMult(&x), new(curve25519.ConstantTimePublicKey).ScalarMultPrecomputed(&y, crypto.GeneratorT))
	curve25519.RandomPoint(&I, rng)
	curve25519.RandomPoint(&C, rng)

	L.ScalarMult(&x, &I)

	rerandomizedOutput := RerandomizeOutput(&O, &I, &C, rng)
	input := rerandomizedOutput.Input()
	opening := OpenInput(&rerandomizedOutput, &x, &y)
	L_, sal := opening.Prove(types.ZeroHash, rng)
	if L.Equal(&L_) == 0 {
		t.Fatalf("L does not equal L_ (%x != %x)", L.Bytes(), L_.Bytes())
	}
	var verifier multiexp.BatchVerifier[struct{}, curve25519.ConstantTimeOperations]
	sal.Verify(&verifier, types.ZeroHash, input, &L, rng)
	if !verifier.Verify() {
		t.Fatalf("batch verifier does not verify")
	}
}
