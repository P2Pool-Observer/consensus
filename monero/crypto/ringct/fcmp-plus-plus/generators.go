package fcmp_plus_plus

import (
	"fmt"
	"slices"
	"sync"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	generalized_bulletproofs "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/helioselene/helios"
	"git.gammaspectra.live/P2Pool/helioselene/selene"
)

var SeleneGeneratorsSize, HeliosGeneratorsSize = IPARows(MaxInputs, MaxLayers)

func rejectionSamplingHashToCurve[P any, V curve.Point[P]](data string, G *P) *P {
	buf := crypto.Keccak256([]byte(data))

	for {
		// Check this is a valid point
		if _, err := V(G).SetBytes(buf[:]); err == nil {
			// Check the point is canonically encoded, which `from_bytes` doesn't guarantee, and not the identity point
			if slices.Equal(V(G).Bytes(), buf[:]) && V(G).IsIdentity() == 0 {
				return G
			}
		}

		buf = crypto.Keccak256(buf[:])
	}
}

var HeliosHashInit = rejectionSamplingHashToCurve("Monero Helios Hash Initializer", new(helios.Point))
var SeleneHashInit = rejectionSamplingHashToCurve("Monero Selene Hash Initializer", new(selene.Point))

// Lazy generator init

var HeliosGenerators = sync.OnceValue(func() *generalized_bulletproofs.Generators[helios.Point] {
	return initGenerators[helios.Point, helios.Scalar, helios.Field]("Helios", HeliosGeneratorsSize)
})
var SeleneGenerators = sync.OnceValue(func() *generalized_bulletproofs.Generators[selene.Point] {
	return initGenerators[selene.Point, selene.Scalar, selene.Field]("Selene", SeleneGeneratorsSize)
})

func initGenerators[P any, S any, F any, V HSPoint[P, S, F, VF], VF curve.Field[F]](id string, size int) *generalized_bulletproofs.Generators[P] {

	G := rejectionSamplingHashToCurve[P, V](fmt.Sprintf("Monero %s G", id), new(P))
	H := rejectionSamplingHashToCurve[P, V](fmt.Sprintf("Monero %s H", id), new(P))

	GBold := make([]*P, size)
	HBold := make([]*P, size)
	for i := range size {
		GBold[i] = new(P)
		HBold[i] = new(P)
	}

	// parallelize
	if err := utils.SplitWork(0, uint64(size), func(workIndex uint64, workerIndex int) error {
		i := workIndex
		rejectionSamplingHashToCurve[P, V](fmt.Sprintf("Monero %s G %d", id, i), GBold[i])
		rejectionSamplingHashToCurve[P, V](fmt.Sprintf("Monero %s H %d", id, i), HBold[i])

		return nil
	}, nil); err != nil {
		panic(err)
	}

	g, err := generalized_bulletproofs.NewGenerators[P, V](G, H, GBold, HBold)
	if err != nil {
		panic(err)
	}
	return g
}
