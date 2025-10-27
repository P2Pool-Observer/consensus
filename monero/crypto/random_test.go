package crypto

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestRandomScalar(t *testing.T) {
	results := GetTestEntries("random_scalar", 1)
	if results == nil {
		t.Fatal()
	}

	rng := NewDeterministicTestGenerator()

	for e := range results {
		expected := curve25519.PrivateKeyBytes(types.MustHashFromString(e[0]))

		key := RandomScalar(new(curve25519.Scalar), rng)

		if curve25519.PrivateKeyBytes(key.Bytes()) != expected {
			t.Errorf("expected %s, got %x", expected.String(), key.Bytes())
		}
	}

	t.Logf("rng permutations: %d", rng.Permutations())
}
