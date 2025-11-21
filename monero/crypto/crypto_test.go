package crypto

import (
	"os"
	"path"
	"runtime"
	"strings"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func init() {
	_, filename, _, _ := runtime.Caller(0)
	// The ".." may change depending on you folder structure
	dir := path.Join(path.Dir(filename), "../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

}

func GetTestEntriesCustom(path, name string, n int) chan []string {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	result := make(chan []string)
	go func() {
		defer close(result)
		for _, line := range strings.Split(string(buf), "\n") {
			entries := strings.Split(strings.TrimSpace(line), " ")
			if entries[0] == name && len(entries) >= (n+1) {
				result <- entries[1:]
			}
		}
	}()
	return result
}

func GetTestEntries(name string, n int) chan []string {
	return GetTestEntriesCustom("testdata/monero_crypto_tests.txt", name, n)
}

/*
	TestCheckTorsion Generated via:

var results [][]string

results = append(results, []string{PublicKeyFromPoint(I).String(), "false"})
results = append(results, []string{PublicKeyFromPoint(G).String(), "true"})

	for _, Q := range edwards25519.EightTorsion[1:] {
		if PublicKeyFromPoint(Q).AsBytes() == ZeroPublicKeyBytes {
			continue
		}
		results = append(results, []string{PublicKeyFromPoint(Q).String(), "false"})
	}

	for _, Q := range edwards25519.EightTorsion[1:] {
		var PQ edwards25519.Point
		PQ.Add(G, Q)
		results = append(results, []string{PublicKeyFromPoint(&PQ).String(), "false"})
	}

	for i, Q := range edwards25519.EightTorsion[1:] {
		var PQ edwards25519.Point
		PQ.ScalarBaseMult(DeterministicScalar([]byte{uint8(i)}))
		results = append(results, []string{PublicKeyFromPoint(&PQ).String(), "true"})
		PQ.Add(&PQ, Q)
		results = append(results, []string{PublicKeyFromPoint(&PQ).String(), "false"})
	}

	for _, e := range results {
		fmt.Printf("check_torsion %s\n", strings.Join(e, " "))
	}
*/
func TestCheckTorsion(t *testing.T) {
	results := GetTestEntriesCustom("testdata/p2pool_crypto_tests.txt", "check_torsion", 2)

	if results == nil {
		t.Fatal()
	}
	for e := range results {
		key := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0])
		result := e[1] == "true"

		if p := key.Point(); p == nil {
			if result {
				t.Errorf("expected not nil")
			}
		} else if p.IsSmallOrder() || !p.IsTorsionFree() {
			if result {
				t.Errorf("expected valid")
			}
		} else if !result {
			t.Errorf("expected not valid")
		}
	}
}

func TestCheckTorsionVarTime(t *testing.T) {
	results := GetTestEntriesCustom("testdata/p2pool_crypto_tests.txt", "check_torsion", 2)

	if results == nil {
		t.Fatal()
	}
	for e := range results {
		key := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0])
		result := e[1] == "true"

		if p := key.PointVarTime(); p == nil {
			if result {
				t.Errorf("expected not nil")
			}
		} else if p.IsSmallOrder() || !p.IsTorsionFree() {
			if result {
				t.Errorf("expected valid")
			}
		} else if !result {
			t.Errorf("expected not valid")
		}
	}
}

func TestCheckScalar(t *testing.T) {
	results := GetTestEntries("check_scalar", 2)
	if results == nil {
		t.Fatal()
	}
	for e := range results {
		key := types.MustBytes32FromString[curve25519.PrivateKeyBytes](e[0])
		result := e[1] == "true"

		if key.Scalar() == nil {
			if result {
				t.Errorf("expected not nil")
			}
		} else if !result {
			t.Errorf("expected nil, got %x\n", key.Scalar().Bytes())
		}
	}
}

func TestSecretKeyToPublicKey(t *testing.T) {
	results := GetTestEntries("secret_key_to_public_key", 2)
	if results == nil {
		t.Fatal()
	}
	for e := range results {
		key := types.MustBytes32FromString[curve25519.PrivateKeyBytes](e[0])
		result := e[1] == "true"
		var expected curve25519.PublicKeyBytes
		if len(e) > 2 {
			expected = types.MustBytes32FromString[curve25519.PublicKeyBytes](e[2])
		}

		if key.Scalar() == nil {
			if result {
				t.Errorf("expected not nil")
			}
			continue
		} else if !result {
			t.Errorf("expected nil, got %x\n", key.Scalar().Bytes())
			continue
		}

		pub := new(curve25519.ConstantTimePublicKey).ScalarBaseMult(key.Scalar()).AsBytes()
		if pub != expected {
			t.Errorf("expected %s, got %s", expected.String(), pub.String())
		}
	}
}

func TestGenerateKeys(t *testing.T) {
	results := GetTestEntries("generate_keys", 2)
	if results == nil {
		t.Fatal()
	}
	rng := NewDeterministicTestGenerator()

	rng.Skip(263)

	for e := range results {
		expectedPub := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0])
		expectedPriv := types.MustBytes32FromString[curve25519.PrivateKeyBytes](e[1])

		key := curve25519.RandomScalar(new(curve25519.Scalar), rng)

		pub := new(curve25519.ConstantTimePublicKey).ScalarBaseMult(key)

		if curve25519.PrivateKeyBytes(key.Bytes()) != expectedPriv {
			t.Errorf("expected %s, got %x", expectedPriv.String(), key.Bytes())
		} else if pub.AsBytes() != expectedPub {
			t.Errorf("expected %s, got %s", expectedPub.String(), pub.String())
		}
	}

	t.Logf("rng permutations: %d", rng.Permutations())
}

func TestCheckKey(t *testing.T) {
	t.Run("Constant", func(t *testing.T) {
		results := GetTestEntries("check_key", 2)
		if results == nil {
			t.Fatal()
		}
		for e := range results {
			key := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0])
			result := e[1] == "true"

			if k, err := new(curve25519.ConstantTimePublicKey).SetBytes(key[:]); err != nil {
				if result {
					t.Errorf("expected not nil")
				}
			} else if !result {
				t.Errorf("expected nil, got %s\n", k.String())
			}
		}
	})

	t.Run("Variable", func(t *testing.T) {
		results := GetTestEntries("check_key", 2)
		if results == nil {
			t.Fatal()
		}
		for e := range results {
			key := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0])
			result := e[1] == "true"

			if k, err := new(curve25519.VarTimePublicKey).SetBytes(key[:]); err != nil {
				if result {
					t.Errorf("expected not nil")
				}
			} else if !result {
				t.Errorf("expected nil, got %s\n", k.String())
			}
		}
	})
}

func TestHashToEC(t *testing.T) {
	results := GetTestEntries("hash_to_ec", 2)
	if results == nil {
		t.Fatal()
	}

	for e := range results {
		key := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0])
		expected := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[1])

		point := BiasedHashToPoint(new(curve25519.ConstantTimePublicKey), key.Slice())

		image := point.AsBytes()

		if image != expected {
			t.Errorf("expected %s, got %s", expected.String(), image.String())
		}
	}
}

func TestHashToPoint(t *testing.T) {
	results := GetTestEntries("hash_to_point", 2)
	if results == nil {
		t.Fatal()
	}

	for e := range results {
		key := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0])
		expected := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[1])

		point := curve25519.Elligator2WithUniformBytes(new(curve25519.ConstantTimePublicKey), key)
		if point == nil {
			t.Errorf("point is nil")
			continue
		}

		image := point.AsBytes()

		if image != expected {
			t.Errorf("%s: expected %s, got %s", key.String(), expected.String(), image.String())
		}
	}
}
