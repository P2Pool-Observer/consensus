package generalized_bulletproofs

import (
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"github.com/tidwall/btree"
)

type Variable interface {
	VarIndex() int
	// TODO VariableAL | VariableAR | VariableAO | VariableCG | VariableV
}

// VariableAL A Variable within the left vector of vectors multiplied against each other.
type VariableAL int

func (v VariableAL) VarIndex() int {
	return int(v)
}

// VariableAR A Variable within the right vector of vectors multiplied against each other.
type VariableAR int

func (v VariableAR) VarIndex() int {
	return int(v)
}

// VariableAO A Variable within the output vector of the left vector multiplied by the right vector.
type VariableAO int

func (v VariableAO) VarIndex() int {
	return int(v)
}

// VariableCG A Variable within a Pedersen vector commitment, committed to with a generator from `g` (bold).
type VariableCG struct {
	// Commitment The commitment being indexed.
	Commitment int
	// Index The index of the variable.
	Index int
}

func (v VariableCG) VarIndex() int {
	return v.Index
}

// VariableV A Variable within a Pedersen commitment.
type VariableV int

func (v VariableV) VarIndex() int {
	return int(v)
}

type CombEntry[F any] struct {
	I int
	F F
}
type LinComb[F any, FE curve.BasicField[F]] struct {
	HighestAIndex int
	HighestCIndex int
	HighestVIndex int

	WL []CombEntry[F]
	WR []CombEntry[F]
	WO []CombEntry[F]

	WCG *btree.Map[int, []CombEntry[F]]

	WV []CombEntry[F]
	C  F
}

func NewEmptyLinComb[F any, FE curve.BasicField[F]]() *LinComb[F, FE] {
	return &LinComb[F, FE]{
		HighestAIndex: -1,
		HighestCIndex: -1,
		HighestVIndex: -1,
		WCG:           btree.NewMap[int, []CombEntry[F]](2),
	}
}

func NewLinCombFrom[F any, FE curve.BasicField[F]](constrainable Variable) *LinComb[F, FE] {
	return NewEmptyLinComb[F, FE]().Term(FE(new(F)).One(), constrainable)
}

func (c *LinComb[F, FE]) Term(scalar *F, constrainable Variable) *LinComb[F, FE] {
	switch v := constrainable.(type) {
	case VariableAL:
		c.HighestAIndex = max(c.HighestAIndex, int(v))
		c.WL = append(c.WL, CombEntry[F]{I: int(v), F: *scalar})
	case VariableAR:
		c.HighestAIndex = max(c.HighestAIndex, int(v))
		c.WR = append(c.WR, CombEntry[F]{I: int(v), F: *scalar})
	case VariableAO:
		c.HighestAIndex = max(c.HighestAIndex, int(v))
		c.WO = append(c.WO, CombEntry[F]{I: int(v), F: *scalar})
	case VariableCG:
		c.HighestCIndex = max(c.HighestCIndex, v.Commitment)
		/*
		   We use `highest_a_index` to track the highest index within the IPA, hence why it tracks
		   indexes to `aL`, `aR`, and `aO`. The variables within a vector commitment are _also_
		   dependent on the size of the IPA, hence why these _also_ update `highest_a_index`.
		*/
		c.HighestAIndex = max(c.HighestAIndex, v.Index)

		e, _ := c.WCG.Get(v.Commitment)
		c.WCG.Set(v.Commitment, append(e, CombEntry[F]{I: v.Index, F: *scalar}))
	case VariableV:
		c.HighestVIndex = max(c.HighestVIndex, int(v))
		c.WV = append(c.WV, CombEntry[F]{I: int(v), F: *scalar})
	default:
		panic("invalid constrainable type")
	}
	return c
}

func (c *LinComb[F, FE]) reconcileForMerging(other *LinComb[F, FE]) {
	c.HighestAIndex = max(c.HighestAIndex, other.HighestAIndex)
	c.HighestCIndex = max(c.HighestCIndex, other.HighestCIndex)
	c.HighestVIndex = max(c.HighestVIndex, other.HighestVIndex)
}

func (c *LinComb[F, FE]) Add(other *LinComb[F, FE]) *LinComb[F, FE] {
	c.reconcileForMerging(other)
	c.WL = append(c.WL, other.WL...)
	c.WR = append(c.WR, other.WR...)
	c.WO = append(c.WO, other.WO...)
	other.WCG.Scan(func(key int, value []CombEntry[F]) bool {
		e, ok := c.WCG.Get(key)
		if ok {
			e = append(e, value...)
		} else {
			// clone to prevent modifications
			e = slices.Clone(value)
		}
		c.WCG.Set(key, e)
		return true
	})
	c.WV = append(c.WV, other.WV...)
	FE(&c.C).Add(&c.C, &other.C)

	return c
}

func (c *LinComb[F, FE]) Subtract(other *LinComb[F, FE]) *LinComb[F, FE] {
	c.reconcileForMerging(other)
	for _, e := range other.WL {
		c.WL = append(c.WL, CombEntry[F]{I: e.I, F: *FE(new(F)).Negate(&e.F)})
	}
	for _, e := range other.WR {
		c.WR = append(c.WR, CombEntry[F]{I: e.I, F: *FE(new(F)).Negate(&e.F)})
	}
	for _, e := range other.WO {
		c.WO = append(c.WO, CombEntry[F]{I: e.I, F: *FE(new(F)).Negate(&e.F)})
	}
	other.WCG.Scan(func(key int, value []CombEntry[F]) bool {
		e, _ := c.WCG.Get(key)
		for _, v := range value {
			e = append(e, CombEntry[F]{I: v.I, F: *FE(new(F)).Negate(&v.F)})
		}
		c.WCG.Set(key, e)
		return true
	})
	for _, e := range other.WV {
		c.WV = append(c.WV, CombEntry[F]{I: e.I, F: *FE(new(F)).Negate(&e.F)})
	}
	FE(&c.C).Subtract(&c.C, &other.C)

	return c
}

func (c *LinComb[F, FE]) Multiply(scalar *F) *LinComb[F, FE] {
	for i := range c.WL {
		FE(&c.WL[i].F).Multiply(&c.WL[i].F, scalar)
	}
	for i := range c.WR {
		FE(&c.WR[i].F).Multiply(&c.WR[i].F, scalar)
	}
	for i := range c.WO {
		FE(&c.WO[i].F).Multiply(&c.WO[i].F, scalar)
	}
	c.WCG.Scan(func(key int, value []CombEntry[F]) bool {
		// modify in-place
		for i := range value {
			FE(&value[i].F).Multiply(&value[i].F, scalar)
		}
		return true
	})
	for i := range c.WV {
		FE(&c.WV[i].F).Multiply(&c.WV[i].F, scalar)
	}
	FE(&c.C).Multiply(&c.C, scalar)
	return c
}

func (c *LinComb[F, FE]) Constant(scalar *F) *LinComb[F, FE] {
	FE(&c.C).Add(&c.C, scalar)
	return c
}

// AccumulateVector Accumulate a sparse vector into an accumulator with a multiplicative weight applied.
func AccumulateVector[F any, FE curve.BasicField[F]](accumulator ScalarVector[F, FE], values []CombEntry[F], weight *F) (hi int) {
	var tmp F
	for _, coeff := range values {
		FE(&tmp).Multiply(&coeff.F, weight)
		FE(&accumulator[coeff.I]).Add(&accumulator[coeff.I], &tmp)
		hi = max(hi, coeff.I)
	}
	return hi
}
