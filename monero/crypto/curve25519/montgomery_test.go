package curve25519

import (
	"fmt"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type x25519TestVector struct {
	Scalar PrivateKeyBytes
	Point  MontgomeryPoint
	Result MontgomeryPoint
}

func newX25519TestVector(sc, pt, re string) x25519TestVector {
	return x25519TestVector{
		Scalar: types.MustBytes32FromString[PrivateKeyBytes](sc),
		Point:  types.MustBytes32FromString[MontgomeryPoint](pt),
		Result: types.MustBytes32FromString[MontgomeryPoint](re),
	}
}

// x25519TestVectors Vectors from https://github.com/jeffro256/mx25519/blob/3c3a36d77d7a10e328cbffc2cf2c2bb59ced9d9a/tests/tests.c
var x25519TestVectors = []x25519TestVector{
	// RFC 7748 test vectors
	// the second most significant bit of each private key was set to 1 to match the RFC results
	newX25519TestVector(
		"a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
		"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
		"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
	),
	newX25519TestVector(
		"4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d",
		"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
		"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
	),

	// base point >2^255-19
	newX25519TestVector(
		"a82b2c3964e188a899d6f74b99679013b0a2510b5a6a0a90739e444b23f7bae6",
		"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"18b1569101d55e0e7e8527a73e27d43393a2d4ec73e67078064bc2a56dcb5860",
	),

	// scalar with bit 254 set to 0
	newX25519TestVector(
		"a8c58a54782e87c7052458c2caa461aa27024fb08801ad4bb376b880e449da88",
		"08558f428dff0dc8ee4bebf2408982cf65538a3ae57dffe4f49f43f5506ccd09",
		"cd178e864e4f3dd3f5e945c04b87825b84d8a224b6c240784515c5f87af27647",
	),
}

func TestX25519(t *testing.T) {
	t.Run("ScalarBaseMult", func(t *testing.T) {
		t.Run("One", func(t *testing.T) {
			one := (&PrivateKeyBytes{1}).Scalar()
			var pub MontgomeryPoint
			MontgomeryScalarBaseMult[VarTimeOperations](&pub, one)

			if pub != MontgomeryBasepoint {
				t.Errorf("expected %s, got %s", MontgomeryBasepoint.String(), pub.String())
			}
		})
	})
	t.Run("ScalarMult", func(t *testing.T) {
		for i, vec := range x25519TestVectors {
			t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
				var pub MontgomeryPoint
				MontgomeryUnclampedScalarMult(&pub, vec.Scalar, vec.Point)

				if pub != vec.Result {
					t.Errorf("expected %s, got %s", vec.Result.String(), pub.String())
				}
			})
		}
	})
}

func BenchmarkX25519ScalarMult(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var n int
		var pub MontgomeryPoint
		for pb.Next() {
			vec := x25519TestVectors[n%len(x25519TestVectors)]
			MontgomeryUnclampedScalarMult(&pub, vec.Scalar, vec.Point)
			n++
		}
	})
}
