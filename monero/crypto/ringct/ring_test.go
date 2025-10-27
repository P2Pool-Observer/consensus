package ringct

import (
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

func init() {
	_, filename, _, _ := runtime.Caller(0)
	// The ".." may change depending on you folder structure
	dir := path.Join(path.Dir(filename), "../../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

}

func GetTestEntries(name string, n int) chan []string {
	buf, err := os.ReadFile("testdata/monero_crypto_tests.txt")
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

func TestCheckRingSignature(t *testing.T) {
	results := GetTestEntries("check_ring_signature", 3)
	if results == nil {
		t.Fatal()
	}

	i := 0
	for e := range results {

		expected := e[len(e)-1] == "true"

		if err := func() error {
			prefixHash := types.MustHashFromString(e[0])
			keyImage := curve25519.DecodeCompressedPoint[curve25519.VarTimeOperations](new(curve25519.VarTimePublicKey), types.MustBytes32FromString[curve25519.PublicKeyBytes](e[1]))

			if keyImage == nil {
				return errors.New("keyImage is nil")
			}

			count, err := strconv.ParseUint(e[2], 10, 64)
			if err != nil {
				t.Fatal(err)
			}

			e = e[3:]
			if len(e) != int(count)+1+1 {
				return fmt.Errorf("expected %d elements, got %d", int(count)+1+1, len(e))
			}

			var rs RingSignature[curve25519.VarTimeOperations]

			for range count {
				pub := curve25519.DecodeCompressedPoint[curve25519.VarTimeOperations](new(curve25519.VarTimePublicKey),
					types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0]),
				)
				if pub == nil {
					return errors.New("pub is nil")
				}
				rs.Ring = append(rs.Ring, *pub)
				e = e[1:]
			}

			sigData, err := hex.DecodeString(e[0])
			if err != nil {
				return err
			}
			for range count {
				sig := crypto.NewSignatureFromBytes[curve25519.VarTimeOperations](sigData[:curve25519.PrivateKeySize*2])
				if sig == nil {
					return errors.New("sig is nil")
				}
				rs.Signatures = append(rs.Signatures, *sig)
				sigData = sigData[curve25519.PrivateKeySize*2:]
			}

			result := rs.Verify(prefixHash, keyImage)
			if result != true {
				return errors.New("invalid signature")
			}
			return nil
		}(); err != nil && expected {
			t.Errorf("#%d: expected: %v, got: %v, err: %s", i, expected, false, err)
		} else if err == nil && !expected {
			t.Errorf("#%d: expected: %v, got: %v", i, expected, true)
		}
		i++
	}
}

func TestGenerateRingSignature(t *testing.T) {
	results := GetTestEntries("generate_ring_signature", 3)
	if results == nil {
		t.Fatal()
	}
	rng := crypto.NewDeterministicTestGenerator()

	rng.Skip(809)

	i := 0
	for e := range results {
		if err := func() error {
			prefixHash := types.MustHashFromString(e[0])
			keyImage := curve25519.DecodeCompressedPoint[curve25519.ConstantTimeOperations](new(curve25519.ConstantTimePublicKey), types.MustBytes32FromString[curve25519.PublicKeyBytes](e[1]))

			if keyImage == nil {
				return errors.New("keyImage is nil")
			}

			count, err := strconv.ParseUint(e[2], 10, 64)
			if err != nil {
				t.Fatal(err)
			}

			e = e[3:]
			if len(e) != int(count)+1+1+1 {
				return fmt.Errorf("expected %d elements, got %d", int(count)+1+1+2, len(e))
			}

			var rs RingSignature[curve25519.ConstantTimeOperations]

			for range count {
				pub := curve25519.DecodeCompressedPoint[curve25519.ConstantTimeOperations](new(curve25519.ConstantTimePublicKey),
					types.MustBytes32FromString[curve25519.PublicKeyBytes](e[0]),
				)
				if pub == nil {
					return errors.New("pub is nil")
				}
				rs.Ring = append(rs.Ring, *pub)
				e = e[1:]
			}

			secret := types.MustBytes32FromString[curve25519.PrivateKeyBytes](e[0])

			keyPair := crypto.NewKeyPairFromPrivate[curve25519.ConstantTimeOperations](secret.Scalar())

			// derive key image
			image := crypto.GetKeyImage(new(curve25519.ConstantTimePublicKey), keyPair)
			if image.Equal(keyImage) == 0 {
				return fmt.Errorf("expected key image %s, got %s", keyImage, image)
			}

			secretIndex, err := strconv.ParseInt(e[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}

			sigData, err := hex.DecodeString(e[2])
			if err != nil {
				return err
			}

			expectedSignatures := make([]crypto.Signature[curve25519.ConstantTimeOperations], 0, len(rs.Signatures))
			for range count {
				sig := crypto.NewSignatureFromBytes[curve25519.ConstantTimeOperations](sigData[:curve25519.PrivateKeySize*2])
				if sig == nil {
					return errors.New("sig is nil")
				}
				expectedSignatures = append(expectedSignatures, *sig)
				sigData = sigData[curve25519.PrivateKeySize*2:]
			}

			rs.Sign(prefixHash, keyPair, int(secretIndex), rng)
			for i, sig := range rs.Signatures {
				sig2 := expectedSignatures[i]
				if sig.C.Equal(&sig2.C) == 0 {
					return errors.New("C != C'")
				}
				if sig.R.Equal(&sig2.R) == 0 {
					return errors.New("R != R'")
				}
			}

			if !rs.Verify(prefixHash, keyImage) {
				return errors.New("invalid signature")
			}

			return nil
		}(); err != nil {
			t.Errorf("#%d: err: %s", i, err)
		}
		i++
	}

	t.Logf("rng permutations: %d", rng.Permutations())
}
