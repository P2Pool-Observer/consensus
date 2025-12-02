package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/edwards25519" //nolint:depguard
)

func inlineKeccak[T ~[]byte | ~string](data T) []byte {
	h := Keccak256(data)
	return h[:]
}

var (
	// GeneratorG generator of 𝔾E
	// G = {x, 4/5 mod q}
	GeneratorG = curve25519.NewGenerator(edwards25519.NewGeneratorPoint())

	// GeneratorH H_p^1(G)
	// H = 8*to_point(keccak(G))
	// note: this does not use the point_from_bytes() function found in H_p(), instead directly interpreting the
	//       input bytes as a compressed point (this can fail, so should not be used generically)
	// note2: to_point(keccak(G)) is known to succeed for the canonical value of G (it will fail 7/8ths of the time
	//        normally)
	//
	// Contrary to convention (`G` for values, `H` for randomness), `H` is used by Monero for amounts within Pedersen commitments
	GeneratorH = curve25519.NewGenerator(HopefulHashToPoint(new(curve25519.VarTimePublicKey), GeneratorG.Point.Bytes()).P())

	// GeneratorT H_p^2(Keccak256("Monero Generator T"))
	// Used to blind the key-image commitment present within output keys
	GeneratorT = curve25519.NewGenerator(UnbiasedHashToPoint(new(curve25519.VarTimePublicKey), inlineKeccak("Monero Generator T")).P())

	// GeneratorU H_p^2(Keccak256("Monero FCMP++ Generator U"))
	// FCMP++s's key-image generator blinding generator U
	GeneratorU = curve25519.NewGenerator(UnbiasedHashToPoint(new(curve25519.VarTimePublicKey), inlineKeccak("Monero FCMP++ Generator U")).P())

	// GeneratorV H_p^2(Keccak256("Monero FCMP++ Generator V"))
	// FCMP++s's randomness commitment generator V
	GeneratorV = curve25519.NewGenerator(UnbiasedHashToPoint(new(curve25519.VarTimePublicKey), inlineKeccak("Monero FCMP++ Generator V")).P())
)
