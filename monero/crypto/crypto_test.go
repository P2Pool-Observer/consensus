package crypto

import (
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
	fasthex "github.com/tmthrgd/go-hex"
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

func TestDeriveViewTag(t *testing.T) {
	results := GetTestEntries("derive_view_tag", 3)
	if results == nil {
		t.Fatal()
	}

	for e := range results {
		derivation := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		outputIndex, _ := strconv.ParseUint(e[1], 10, 0)
		result, _ := fasthex.DecodeString(e[2])

		viewTag := GetDerivationViewTagForOutputIndex(derivation, outputIndex)

		var tmp edwards25519.Scalar
		viewTag2 := GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(&tmp, derivation, outputIndex)

		if viewTag != viewTag2 {
			t.Errorf("derive_view_tag differs from no_allocate: %d != %d", viewTag, &viewTag2)
		}

		if result[0] != viewTag {
			t.Errorf("expected %s, got %s", fasthex.EncodeToString(result), fasthex.EncodeToString([]byte{viewTag}))
		}
	}
}

func FuzzDeriveViewTag(f *testing.F) {
	results := GetTestEntries("derive_view_tag", 3)
	if results == nil {
		f.Fatal()
	}
	for e := range results {
		derivation := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		outputIndex, _ := strconv.ParseUint(e[1], 10, 0)

		f.Add(derivation.Slice(), outputIndex)
	}

	f.Fuzz(func(t *testing.T, derivation []byte, outputIndex uint64) {
		if len(derivation) != curve25519.PublicKeySize {
			return
		}
		derivationBytes := curve25519.PublicKeyBytes(derivation)

		viewTag := GetDerivationViewTagForOutputIndex(derivationBytes, outputIndex)

		var tmp edwards25519.Scalar
		viewTag2 := GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(&tmp, derivationBytes, outputIndex)

		if viewTag != viewTag2 {
			t.Errorf("derive_view_tag differs from no_allocate: %d != %d", viewTag, &viewTag2)
		}
	})

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
		key := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
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
		key := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		result := e[1] == "true"

		if p := curve25519.To[curve25519.VarTimeOperations](key.Point()); p == nil {
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
		key := curve25519.PrivateKeyBytes(types.MustHashFromString(e[0]))
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
		key := curve25519.PrivateKeyBytes(types.MustHashFromString(e[0]))
		result := e[1] == "true"
		var expected curve25519.PublicKeyBytes
		if len(e) > 2 {
			expected = curve25519.PublicKeyBytes(types.MustHashFromString(e[2]))
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

		pub := new(curve25519.ConstantTimePublicKey).ScalarBaseMult(key.Scalar()).Bytes()
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
		expectedPub := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		expectedPriv := curve25519.PrivateKeyBytes(types.MustHashFromString(e[1]))

		key := RandomScalar(new(edwards25519.Scalar), rng)

		pub := new(curve25519.ConstantTimePublicKey).ScalarBaseMult(key)

		if curve25519.PrivateKeyBytes(key.Bytes()) != expectedPriv {
			t.Errorf("expected %s, got %x", expectedPriv.String(), key.Bytes())
		} else if pub.Bytes() != expectedPub {
			t.Errorf("expected %s, got %s", expectedPub.String(), pub.String())
		}
	}

	t.Logf("rng permutations: %d", rng.Permutations())
}

func TestCheckKey(t *testing.T) {
	results := GetTestEntries("check_key", 2)
	if results == nil {
		t.Fatal()
	}
	for e := range results {
		key := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		result := e[1] == "true"

		if key.Point() == nil {
			if result {
				t.Errorf("expected not nil")
			}
		} else if !result {
			t.Errorf("expected nil, got %s\n", key.Point().String())
		}
	}
}

func TestHashToEC(t *testing.T) {
	results := GetTestEntries("hash_to_ec", 2)
	if results == nil {
		t.Fatal()
	}

	for e := range results {
		key := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		expected := curve25519.PublicKeyBytes(types.MustHashFromString(e[1]))

		point := BiasedHashToPoint(new(curve25519.ConstantTimePublicKey), key.Slice())

		image := point.Bytes()

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
		key := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		expected := curve25519.PublicKeyBytes(types.MustHashFromString(e[1]))

		point := curve25519.Elligator2WithUniformBytes(new(curve25519.ConstantTimePublicKey), key)
		if point == nil {
			t.Errorf("point is nil")
			continue
		}

		image := point.Bytes()

		if image != expected {
			t.Errorf("%s: expected %s, got %s", key.String(), expected.String(), image.String())
		}
	}
}
