package crypto

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type pointTestData struct {
	Name      string
	Generator *curve25519.Generator
	Expected  string
}

func TestReproduceGenerators(t *testing.T) {

	for _, e := range []pointTestData{
		{"GeneratorG", GeneratorG, "5866666666666666666666666666666666666666666666666666666666666666"},
		{"GeneratorH", GeneratorH, "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"},
		{"GeneratorT", GeneratorT, "dc42e1d3307b2d4b3b02729abe577e231d79478141cb5b310ca9fa6e127616a3"},
		{"GeneratorU", GeneratorU, "8a948e2854073aa0bcb82f863c80865b5cc9be179723fc1cbf1c25b885597e54"},
		{"GeneratorV", GeneratorV, "1a423509f7675e912011d14b5610a857ddd588733413b515e003bc4055855bf1"},
	} {
		t.Run(e.Name, func(t *testing.T) {
			h, err := types.HashFromString(e.Expected)
			if err != nil {
				t.Fatal(err)
			}

			expected := curve25519.PublicKeyBytes(h)

			{
				p := curve25519.FromPoint[curve25519.VarTimeOperations](e.Generator.Point).AsBytes()
				if p != expected {
					t.Fatalf("got %s, expected %s", p.String(), expected.String())
				} else {
					t.Logf("match %s", expected.String())
				}
			}
			{
				p := curve25519.FromPoint[curve25519.ConstantTimeOperations](e.Generator.Point).AsBytes()
				if p != expected {
					t.Fatalf("got %s, expected %s", p.String(), expected.String())
				} else {
					t.Logf("match %s", expected.String())
				}
			}
		})
	}
}
