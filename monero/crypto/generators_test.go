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
		{"GeneratorT", GeneratorT, "61b736ce93b62a3d3778ab204da85d3b4cdc07250f5da7e3df2629928134d526"},
		{"GeneratorU", GeneratorU, types.Hash{80, 107, 35, 246, 214, 229, 48, 153, 122, 188, 172, 198, 253, 52, 119, 52,
			177, 76, 43, 215, 155, 234, 0, 238, 176, 72, 87, 232, 234, 221, 26, 138}.String()},
		{"GeneratorV", GeneratorV, types.Hash{105, 53, 244, 19, 248, 49, 9, 19, 138, 122, 20, 180, 9, 85, 45, 59, 118,
			216, 143, 202, 129, 187, 89, 39, 233, 161, 225, 48, 205, 254, 41, 249}.String()},
	} {
		t.Run(e.Name, func(t *testing.T) {
			h, err := types.HashFromString(e.Expected)
			if err != nil {
				t.Fatal(err)
			}

			expected := curve25519.PublicKeyBytes(h)

			p := curve25519.FromPoint[curve25519.VarTimeOperations](e.Generator.Point).AsBytes()
			if p != expected {
				t.Fatalf("got %s, expected %s", p.String(), expected.String())
			} else {
				t.Logf("match %s", expected.String())
			}
		})
	}
}
