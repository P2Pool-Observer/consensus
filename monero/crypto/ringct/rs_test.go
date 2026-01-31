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
	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/go-hex"
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
			keyImage, _ := new(curve25519.VarTimePublicKey).SetBytes(hex.MustDecodeString(e[1]))

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
			var ring Ring[curve25519.VarTimeOperations]

			for range count {
				pub, _ := new(curve25519.VarTimePublicKey).SetBytes(hex.MustDecodeString(e[0]))
				if pub == nil {
					return errors.New("pub is nil")
				}
				ring = append(ring, *pub)
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
				rs = append(rs, *sig)
				sigData = sigData[curve25519.PrivateKeySize*2:]
			}

			result := rs.Verify(prefixHash, ring, keyImage)
			if !result {
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
			keyImage, _ := new(curve25519.ConstantTimePublicKey).SetBytes(hex.MustDecodeString(e[1]))

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
			var ring Ring[curve25519.ConstantTimeOperations]

			for range count {
				pub, _ := new(curve25519.ConstantTimePublicKey).SetBytes(hex.MustDecodeString(e[0]))
				if pub == nil {
					return errors.New("pub is nil")
				}
				ring = append(ring, *pub)
				e = e[1:]
			}

			secret := types.MustBytes32FromString[curve25519.PrivateKeyBytes](e[0])

			keyPair := crypto.NewKeyPairFromPrivate[curve25519.ConstantTimeOperations](secret.Scalar())

			// derive key image
			image := crypto.GetBiasedKeyImage(new(curve25519.ConstantTimePublicKey), keyPair)
			if image.Equal(keyImage) == 0 {
				return fmt.Errorf("expected key image %s, got %s", keyImage, image)
			}

			secretIndex, err := strconv.ParseInt(e[1], 10, 64)
			if err != nil {
				return err
			}

			if ring.Index(&keyPair.PublicKey) != int(secretIndex) {
				return fmt.Errorf("expected key at index %d, got %d", secretIndex, ring.Index(&keyPair.PublicKey))
			}

			sigData, err := hex.DecodeString(e[2])
			if err != nil {
				return err
			}

			expectedSignatures := make([]crypto.Signature[curve25519.ConstantTimeOperations], 0, len(rs))
			for range count {
				sig := crypto.NewSignatureFromBytes[curve25519.ConstantTimeOperations](sigData[:curve25519.PrivateKeySize*2])
				if sig == nil {
					return errors.New("sig is nil")
				}
				expectedSignatures = append(expectedSignatures, *sig)
				sigData = sigData[curve25519.PrivateKeySize*2:]
			}

			if !rs.Sign(prefixHash, ring, keyPair, rng) {
				return errors.New("error signing")
			}
			for i, sig := range rs {
				sig2 := expectedSignatures[i]
				if sig.C.Equal(&sig2.C) == 0 {
					return errors.New("C != C'")
				}
				if sig.R.Equal(&sig2.R) == 0 {
					return errors.New("R != R'")
				}
			}

			if !rs.Verify(prefixHash, ring, keyImage) {
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

// TestRingSignatureLowOrderGenerator
// Implements an attack on RingSignature based on the low order generator bug
// Disclosed on https://www.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html
// Also https://jonasnick.github.io/blog/2017/05/23/exploiting-low-order-generators-in-one-time-ring-signatures/
func TestRingSignatureLowOrderGenerator(t *testing.T) {

	rng := crypto.NewDeterministicTestGenerator()

	keyPair := crypto.NewKeyPairFromPrivate[curve25519.ConstantTimeOperations](curve25519.RandomScalar(new(curve25519.Scalar), rng))

	t.Logf("secret    = %x", keyPair.PrivateKey.Bytes())
	t.Logf("public    = %x", keyPair.PublicKey.AsBytes())

	var rs RingSignature[curve25519.ConstantTimeOperations]
	var ring Ring[curve25519.ConstantTimeOperations]

	ring = append(ring, keyPair.PublicKey)
	for range 3 {
		ring = append(ring, *new(curve25519.ConstantTimePublicKey).ScalarBaseMult(curve25519.RandomScalar(new(curve25519.Scalar), rng)))
	}

	keyImage := crypto.GetBiasedKeyImage(new(curve25519.ConstantTimePublicKey), keyPair)
	if !rs.Sign(types.ZeroHash, ring, keyPair, rng) {
		t.Fatal("error signing")
	}

	// we have a passing ring signature for keyImage
	if !rs.Verify(types.ZeroHash, ring, keyImage) {
		t.Fatal("signature verification failed")
	}

	// prepare a low order point to twist key image
	const torsionIndex = 1
	torsion := curve25519.FromPoint[curve25519.ConstantTimeOperations](edwards25519.EightTorsion[torsionIndex])
	if torsion.P().Equal(edwards25519.NewIdentityPoint()) == 1 {
		t.Fatal("torsion must not be identity")
	}
	if torsion.IsTorsionFree() {
		t.Fatal("torsion must not be torsion free")
	}

	// it's twisting time!
	torsionedKeyImage := new(curve25519.ConstantTimePublicKey).Add(keyImage, torsion)

	// prepare twisted ring signature commiting to new key image, but same private key and ring
	var trs RingSignature[curve25519.ConstantTimeOperations]

	t.Logf("image     = %s", keyImage)

	// it may take a few tries due to random trials
	for i := range 1024 {
		// keep signing until e*I = e*I', given o divides e
		trs.sign(types.ZeroHash, ring, torsionedKeyImage, &keyPair.PrivateKey, 0, rng)

		// check if we are twisted all over
		if !trs.verify(types.ZeroHash, ring, torsionedKeyImage) {
			continue
		}
		if trs.Verify(types.ZeroHash, ring, torsionedKeyImage) {
			t.Errorf("torsioned image I' = I + E[%d] returned true on RingSignature.verify, true on RingSignature.Verify (expected false)", torsionIndex)
		} else {

			t.Logf("torsioned = %s", torsionedKeyImage)
			t.Logf("torsioned image I' = I + E[%d] returned true on RingSignature.verify, false on RingSignature.Verify", torsionIndex)
			t.Logf("took %d tries", i+1)
			return
		}
	}
	t.Fatal("could not find torsioned image")
}
