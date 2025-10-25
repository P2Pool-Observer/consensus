package crypto

import "git.gammaspectra.live/P2Pool/edwards25519"

func inlineKeccak[T ~[]byte | ~string](data T) []byte {
	h := Keccak256(data)
	return h[:]
}

type Generator struct {
	// Point The point used as Generator
	Point *edwards25519.Point
	// Table Precomputed table of Point to be used in VarTime Precomputed scalar point multiplication
	Table *edwards25519.PrecomputedTable
}

func newGenerator(point *edwards25519.Point) *Generator {
	return &Generator{
		Point: point,
		Table: edwards25519.PointTablePrecompute(point),
	}
}

var (
	// GeneratorG generator of 𝔾E
	// G = {x, 4/5 mod q}
	GeneratorG = newGenerator(edwards25519.NewGeneratorPoint())

	// GeneratorH H_p^1(G)
	// H = 8*to_point(keccak(G))
	// note: this does not use the point_from_bytes() function found in H_p(), instead directly interpreting the
	//       input bytes as a compressed point (this can fail, so should not be used generically)
	// note2: to_point(keccak(G)) is known to succeed for the canonical value of G (it will fail 7/8ths of the time
	//        normally)
	//
	// Contrary to convention (`G` for values, `H` for randomness), `H` is used by Monero for amounts within Pedersen commitments
	GeneratorH = newGenerator(HopefulHashToPoint(new(edwards25519.Point), GeneratorG.Point.Bytes()))

	// GeneratorT H_p^2(Keccak256("Monero Generator T"))
	// Used to blind the key-image commitment present within output keys
	GeneratorT = newGenerator(UnbiasedHashToPoint(new(edwards25519.Point), inlineKeccak("Monero Generator T")))

	// GeneratorU H_p^2(Keccak256("Monero FCMP++ Generator U"))
	// FCMP++s's key-image generator blinding generator U
	GeneratorU = newGenerator(UnbiasedHashToPoint(new(edwards25519.Point), inlineKeccak("Monero FCMP++ Generator U")))

	// GeneratorV H_p^2(Keccak256("Monero FCMP++ Generator V"))
	// FCMP++s's randomness commitment generator V
	GeneratorV = newGenerator(UnbiasedHashToPoint(new(edwards25519.Point), inlineKeccak("Monero FCMP++ Generator V")))
)
