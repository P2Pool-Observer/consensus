package crypto

import (
	"bytes"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

func TestGenerateSignature(t *testing.T) {
	results := GetTestEntries("generate_signature", 4)
	if results == nil {
		t.Fatal()
	}

	rng := NewDeterministicTestGenerator()

	rng.Skip(537)

	for e := range results {
		prefixHash := types.MustHashFromString(e[0])
		expectedPub := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[1])
		sec := types.MustBytes32FromString[curve25519.PrivateKeyBytes](e[2])
		sigBytes, _ := hex.DecodeString(e[3])
		expectedSig := NewSignatureFromBytes[curve25519.ConstantTimeOperations](sigBytes)

		pub := new(curve25519.ConstantTimePublicKey).ScalarBaseMult(sec.Scalar())

		if pub.AsBytes() != expectedPub {
			t.Errorf("public key does not match: %s != %s", pub.AsBytes(), expectedPub)
			continue
		}

		sig := CreateMessageSignature[curve25519.ConstantTimeOperations](prefixHash, sec.Scalar(), rng)

		if bytes.Compare(sig.Bytes(), expectedSig.Bytes()) != 0 {
			t.Errorf("expected %s, got %s", hex.EncodeToString(sig.Bytes()), hex.EncodeToString(expectedSig.Bytes()))
		}
	}

	t.Logf("rng permutations: %d", rng.Permutations())
}

func TestCheckSignature(t *testing.T) {
	results := GetTestEntries("check_signature", 3)
	if results == nil {
		t.Fatal()
	}
	for e := range results {
		prefixHash := types.MustHashFromString(e[0])
		pub := types.MustBytes32FromString[curve25519.PublicKeyBytes](e[1])
		sigBytes, _ := hex.DecodeString(e[2])
		sig := NewSignatureFromBytes[curve25519.VarTimeOperations](sigBytes)
		result := e[3] == "true"

		if sig == nil {
			if result {
				t.Fatal("expected signature to not be nil")
			}
			continue
		}

		if VerifyMessageSignature(prefixHash, pub.PointVarTime(), *sig) != result {
			t.Fatalf("expected %v, got %v", result, !result)
		}
	}
}
