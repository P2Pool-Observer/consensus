package crypto

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"github.com/tmthrgd/go-hex"
)

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

		if VerifyMessageSignature(prefixHash, &pub, sig) != result {
			t.Fatalf("expected %v, got %v", result, !result)
		}
	}
}
