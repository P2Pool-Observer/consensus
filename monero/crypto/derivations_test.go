package crypto

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
	fasthex "github.com/tmthrgd/go-hex"
)

func TestKeyImageRaw(t *testing.T) {
	sec, _ := fasthex.DecodeString("981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f")

	scalar, _ := (&edwards25519.Scalar{}).SetCanonicalBytes(sec)
	keyImage := GetKeyImage(NewKeyPairFromPrivate(PrivateKeyFromScalar(scalar)))

	if keyImage.String() != "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887" {
		t.Fatalf("key image expected %s, got %s", "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887", keyImage.String())
	}
}

func TestGenerateKeyImage(t *testing.T) {
	results := GetTestEntries("generate_key_image", 3)
	if results == nil {
		t.Fatal()
	}
	for e := range results {
		pub := PublicKeyBytes(types.MustHashFromString(e[0]))
		secret := PrivateKeyBytes(types.MustHashFromString(e[1]))
		expected := PublicKeyBytes(types.MustHashFromString(e[2]))

		if secret.PublicKey().AsBytes() != pub {
			t.Errorf("public key expected %s, got %s", expected.String(), secret.PublicKey().String())
		}

		keyImage := GetKeyImage(NewKeyPairFromPrivate(&secret))

		if keyImage.AsBytes() != expected {
			t.Errorf("expected %s, got %s", expected.String(), keyImage.String())
		}
	}
}
