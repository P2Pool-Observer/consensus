package crypto

import (
	"bytes"
	"testing"

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
		pub := PublicKeyBytes(types.MustHashFromString(e[1]))
		sec := PrivateKeyBytes(types.MustHashFromString(e[2]))
		sigBytes, _ := hex.DecodeString(e[3])
		expectedSig := NewSignatureFromBytes(sigBytes)

		if sec.PublicKey().AsBytes() != pub {
			t.Errorf("public key does not match: %s != %s", sec.PublicKey().AsBytes(), pub)
			continue
		}

		sig := CreateMessageSignature(prefixHash, sec.AsScalar(), rng)

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
		pub := PublicKeyBytes(types.MustHashFromString(e[1]))
		sigBytes, _ := hex.DecodeString(e[2])
		sig := NewSignatureFromBytes(sigBytes)
		result := e[3] == "true"

		if sig == nil {
			if result {
				t.Fatal("expected signature to not be nil")
			}
			continue
		}

		if VerifyMessageSignature(prefixHash, pub.AsPoint(), *sig) != result {
			t.Fatalf("expected %v, got %v", result, !result)
		}
	}
}
