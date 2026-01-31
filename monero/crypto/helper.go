package crypto

import (
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/edwards25519" //nolint:depguard
)

type EvilKind uint64

const (
	EvilKindBase = EvilKind(1 << iota)
	EvilKindDerivation
	EvilKindKeyImage
	EvilKindLowOrder
	EvilKindTorsion
	EvilKindGenerator
)

type EvilPoint[T curve25519.PointOperations] struct {
	curve25519.PublicKey[T]

	Kind EvilKind
}

func (*EvilPoint[T]) IsIdentity() int {
	//TODO implement me
	panic("implement me")
}

func EvilPointGenerator[T curve25519.PointOperations](sourceScalar *curve25519.Scalar, kindsMask ...EvilKind) (pubs []EvilPoint[T]) {

	// random point to do tests with
	keyPair := NewKeyPairFromPrivate[T](sourceScalar)

	biasedImage := GetBiasedKeyImage[T](new(curve25519.PublicKey[T]), keyPair)
	unbiasedImage := GetUnbiasedKeyImage[T](new(curve25519.PublicKey[T]), keyPair)

	pubs = append(pubs,
		EvilPoint[T]{keyPair.PublicKey, EvilKindBase},
		// key images
		EvilPoint[T]{*biasedImage, EvilKindDerivation | EvilKindKeyImage},
		EvilPoint[T]{*unbiasedImage, EvilKindDerivation | EvilKindKeyImage},
		// cofactor mult
		EvilPoint[T]{*new(curve25519.PublicKey[T]).MultByCofactor(&keyPair.PublicKey), EvilKindDerivation},
		// generator derivation
		EvilPoint[T]{*new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&keyPair.PrivateKey, GeneratorH), EvilKindDerivation | EvilKindGenerator},
		EvilPoint[T]{*new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&keyPair.PrivateKey, GeneratorT), EvilKindDerivation | EvilKindGenerator},
		EvilPoint[T]{*new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&keyPair.PrivateKey, GeneratorU), EvilKindDerivation | EvilKindGenerator},
		EvilPoint[T]{*new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&keyPair.PrivateKey, GeneratorV), EvilKindDerivation | EvilKindGenerator},
	)

	// add low order and torsioned points
	for _, torsion := range edwards25519.EightTorsion[1:] {
		pubs = append(pubs,
			EvilPoint[T]{*new(curve25519.PublicKey[T]).Add(&keyPair.PublicKey, curve25519.FromPoint[T](torsion)), EvilKindBase | EvilKindDerivation | EvilKindTorsion},
			EvilPoint[T]{*new(curve25519.PublicKey[T]).Add(biasedImage, curve25519.FromPoint[T](torsion)), EvilKindDerivation | EvilKindTorsion | EvilKindKeyImage},
			EvilPoint[T]{*new(curve25519.PublicKey[T]).Add(unbiasedImage, curve25519.FromPoint[T](torsion)), EvilKindDerivation | EvilKindTorsion | EvilKindKeyImage},
			EvilPoint[T]{*curve25519.FromPoint[T](torsion), EvilKindLowOrder | EvilKindTorsion},
		)
	}

	// special points
	pubs = append(pubs,
		EvilPoint[T]{*curve25519.FromPoint[T](edwards25519.NewGeneratorPoint()), EvilKindGenerator},
		EvilPoint[T]{*curve25519.FromPoint[T](edwards25519.NewIdentityPoint()), EvilKindLowOrder},
	)

	// filter
	for i := len(pubs) - 1; i >= 0; i-- {
		var remove bool
		for _, mask := range kindsMask {
			if pubs[i].Kind&mask == mask {
				remove = false
				break
			} else {
				remove = true
			}
		}
		if remove {
			pubs = slices.Delete(pubs, i, i+1)
		}
	}

	return pubs
}
