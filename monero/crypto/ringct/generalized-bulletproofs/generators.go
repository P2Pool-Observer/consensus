package generalized_bulletproofs

import (
	"errors"
	"math"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type Generators[T any] struct {
	G *T
	H *T

	GBold []*T
	HBold []*T
	HSum  []*T
}

func NewGenerators[P any, V curve.Point[P]](G, H *P, GBold, HBold []*P) (g *Generators[P], err error) {
	if len(GBold) == 0 {
		return nil, errors.New("empty GBold")
	}
	if len(HBold) != len(GBold) {
		return nil, errors.New("length mismatch")
	}
	nx := utils.NextPowerOfTwo(uint(len(GBold)))
	if len(GBold) > (math.MaxInt>>1)+1 || nx != len(GBold) {
		return nil, errors.New("not power of two")
	}

	set := make(map[[32]byte]struct{})
	addGenerator := func(generator *P) error {
		if V(generator).IsIdentity() == 1 {
			return errors.New("generator is identity point")
		}
		buf := [32]byte(V(generator).Bytes())
		if _, ok := set[buf]; ok {
			return errors.New("duplicate generator")
		}
		set[buf] = struct{}{}
		return nil
	}

	if err = addGenerator(G); err != nil {
		return nil, err
	}

	if err = addGenerator(H); err != nil {
		return nil, err
	}

	for _, generator := range GBold {
		if err = addGenerator(generator); err != nil {
			return nil, err
		}
	}

	for _, generator := range HBold {
		if err = addGenerator(generator); err != nil {
			return nil, err
		}
	}

	runningHSum := V(new(P)).Identity()
	var HSum []*P

	nextPowerOf2 := 1

	for i, h := range HBold {
		V(runningHSum).Add(runningHSum, h)
		if (i + 1) == nextPowerOf2 {
			HSum = append(HSum, runningHSum)
			nextPowerOf2 *= 2
		}
	}

	return &Generators[P]{
		G:     G,
		H:     H,
		GBold: GBold,
		HBold: HBold,
		HSum:  HSum,
	}, nil

}
