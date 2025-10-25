package crypto

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestRandomScalar(t *testing.T) {
	results := GetTestEntries("random_scalar", 1)
	if results == nil {
		t.Fatal()
	}

	rng := NewDeterministicTestGenerator()

	for e := range results {
		expected := PrivateKeyBytes(types.MustHashFromString(e[0]))

		key := PrivateKeyFromScalar(RandomScalar(rng))

		if key.AsBytes() != expected {
			t.Errorf("expected %s, got %s", expected.String(), key.String())
		}
	}

	t.Logf("rng permutations: %d", rng.Permutations())
}
