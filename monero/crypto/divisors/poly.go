package divisors

import (
	"encoding/binary"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
)

type CoefficientIndex struct {
	YPow uint64
	XPow uint64
}

// mask64Bits returns 0xffffffff if cond is 1, and 0 otherwise.
func mask64Bits(cond int) uint64 {
	return ^(uint64(cond) - 1)
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *CoefficientIndex) Select(a, b *CoefficientIndex, cond int) *CoefficientIndex {
	m := mask64Bits(cond)
	v.YPow = (m & a.YPow) | (^m & b.YPow)
	v.XPow = (m & a.XPow) | (^m & b.XPow)
	return v
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *CoefficientIndex) Equal(u *CoefficientIndex) int {
	z := (v.YPow ^ u.YPow) | (v.XPow ^ u.XPow)
	return int(1 ^ ((z | -z) >> 63))
}

func select64Bits(a, b uint64, cond int) uint64 {
	m := mask64Bits(cond)
	return (m & a) | (^m & b)
}

func equal64Bits(x, y uint64) int {
	z := x ^ y
	return int(1 ^ ((z | -z) >> 63))
}

func greater64Bits(x, y uint64) int {
	return int(((^y & x) | ((^y | x) & (y - x))) >> 63)
}

// Greater returns 1 if v is greater than u, and 0 otherwise.
func (v *CoefficientIndex) Greater(u *CoefficientIndex) int {
	yGt := greater64Bits(v.YPow, u.YPow)
	yEq := equal64Bits(v.YPow, u.YPow)
	xGt := greater64Bits(v.XPow, u.XPow)
	return yGt | (yEq & xGt)
}

type Poly[F any] struct {
	// YCoefficients c\[i] * y^(i + 1)
	YCoefficients []F
	// YXCoefficients c\[i]\[j] * y^(i + 1) x^(j + 1)
	YXCoefficients [][]F
	// XCoefficients c\[i] * x^(i + 1)
	XCoefficients []F
	// ZeroCoefficient Coefficient for x^0, y^0, and x^0 y^0 (the coefficient for 1)
	ZeroCoefficient F
}

func (p *Poly[F]) Equal[FE curve.Field[F]](o *Poly[F]) bool {

	{
		mutualYCoefficients := min(len(p.YCoefficients), len(o.YCoefficients))

		if !curve.FieldSliceEqualsVarTime[F, FE](p.YCoefficients[:mutualYCoefficients], o.YCoefficients[:mutualYCoefficients]) {
			return false
		}

		for _, coeff := range p.YCoefficients[mutualYCoefficients:] {
			if FE(&coeff).IsZero() == 0 {
				return false
			}
		}
		for _, coeff := range o.YCoefficients[mutualYCoefficients:] {
			if FE(&coeff).IsZero() == 0 {
				return false
			}
		}
	}

	{

		for i, yxCoeffs := range p.YXCoefficients {
			var other []F
			if len(o.YXCoefficients) > i {
				other = o.YXCoefficients[i]
			}
			for j, coeff := range yxCoeffs {
				if len(other) > j {
					if FE(&coeff).Equal(&other[j]) == 0 {
						return false
					}
				} else if FE(&coeff).IsZero() == 0 {
					return false
				}
			}
		}
		// Run from the other perspective in case other is longer than self
		for i, yxCoeffs := range o.YXCoefficients {
			var other []F
			if len(p.YXCoefficients) > i {
				other = p.YXCoefficients[i]
			}
			for j, coeff := range yxCoeffs {
				if len(other) > j {
					if FE(&coeff).Equal(&other[j]) == 0 {
						return false
					}
				} else if FE(&coeff).IsZero() == 0 {
					return false
				}
			}
		}
	}

	{
		mutualXCoefficients := min(len(p.XCoefficients), len(o.XCoefficients))

		if !curve.FieldSliceEqualsVarTime[F, FE](p.XCoefficients[:mutualXCoefficients], o.XCoefficients[:mutualXCoefficients]) {
			return false
		}

		for _, coeff := range p.XCoefficients[mutualXCoefficients:] {
			if FE(&coeff).IsZero() == 0 {
				return false
			}
		}
		for _, coeff := range o.XCoefficients[mutualXCoefficients:] {
			if FE(&coeff).IsZero() == 0 {
				return false
			}
		}
	}

	return FE(&p.ZeroCoefficient).Equal(&o.ZeroCoefficient) == 1
}

func (p *Poly[F]) Clone() *Poly[F] {
	yx := make([][]F, len(p.YXCoefficients))
	for i := range yx {
		yx[i] = slices.Clone(p.YXCoefficients[i])
	}

	return &Poly[F]{
		YCoefficients:   slices.Clone(p.YCoefficients),
		YXCoefficients:  yx,
		XCoefficients:   slices.Clone(p.XCoefficients),
		ZeroCoefficient: p.ZeroCoefficient,
	}
}

func (p *Poly[F]) Set(o *Poly[F]) *Poly[F] {
	p.YCoefficients = slices.Grow(p.YCoefficients, len(o.YCoefficients))[:len(o.YCoefficients)]
	copy(p.YCoefficients, o.YCoefficients)

	p.YXCoefficients = slices.Grow(p.YXCoefficients, len(o.YXCoefficients))[:len(o.YXCoefficients)]
	for i := range p.YXCoefficients {
		p.YXCoefficients[i] = slices.Grow(p.YXCoefficients[i], len(o.YXCoefficients[i]))[:len(o.YXCoefficients[i])]
		copy(p.YXCoefficients[i], o.YXCoefficients[i])
	}

	p.XCoefficients = slices.Grow(p.XCoefficients, len(o.XCoefficients))[:len(o.XCoefficients)]
	copy(p.XCoefficients, o.XCoefficients)

	p.ZeroCoefficient = o.ZeroCoefficient

	return p
}

func (p *Poly[F]) Zero() *Poly[F] {
	var zero F
	p.YCoefficients = p.YCoefficients[:0]
	p.YXCoefficients = p.YXCoefficients[:0]
	p.XCoefficients = p.XCoefficients[:0]

	p.ZeroCoefficient = zero

	return p
}

func (p *Poly[F]) pad[FE curve.BasicField[F]](o *Poly[F]) {
	for len(p.YCoefficients) < len(o.YCoefficients) {
		p.YCoefficients = append(p.YCoefficients, *FE(new(F)).Zero())
	}

	for len(p.YXCoefficients) < len(o.YXCoefficients) {
		p.YXCoefficients = append(p.YXCoefficients, make([]F, 0, len(o.YXCoefficients[len(p.YXCoefficients)])))
	}
	for i := range min(len(p.YXCoefficients), len(o.YXCoefficients)) {
		for len(p.YXCoefficients[i]) < len(o.YXCoefficients[i]) {
			p.YXCoefficients[i] = append(p.YXCoefficients[i], *FE(new(F)).Zero())
		}
	}

	for len(p.XCoefficients) < len(o.XCoefficients) {
		p.XCoefficients = append(p.XCoefficients, *FE(new(F)).Zero())
	}
}

func (p *Poly[F]) Add[FE curve.BasicField[F]](o *Poly[F]) *Poly[F] {
	p.pad[FE](o)

	for i := range o.YCoefficients {
		FE(&p.YCoefficients[i]).Add(&p.YCoefficients[i], &o.YCoefficients[i])
	}
	for i := range o.YXCoefficients {
		for j := range o.YXCoefficients[i] {
			FE(&p.YXCoefficients[i][j]).Add(&p.YXCoefficients[i][j], &o.YXCoefficients[i][j])
		}
	}
	for i := range o.XCoefficients {
		FE(&p.XCoefficients[i]).Add(&p.XCoefficients[i], &o.XCoefficients[i])
	}

	FE(&p.ZeroCoefficient).Add(&p.ZeroCoefficient, &o.ZeroCoefficient)

	return p
}

func (p *Poly[F]) Subtract[FE curve.BasicField[F]](o *Poly[F]) *Poly[F] {
	p.pad[FE](o)

	for i := range o.YCoefficients {
		FE(&p.YCoefficients[i]).Subtract(&p.YCoefficients[i], &o.YCoefficients[i])
	}
	for i := range o.YXCoefficients {
		for j := range o.YXCoefficients[i] {
			FE(&p.YXCoefficients[i][j]).Subtract(&p.YXCoefficients[i][j], &o.YXCoefficients[i][j])
		}
	}
	for i := range o.XCoefficients {
		FE(&p.XCoefficients[i]).Subtract(&p.XCoefficients[i], &o.XCoefficients[i])
	}

	FE(&p.ZeroCoefficient).Subtract(&p.ZeroCoefficient, &o.ZeroCoefficient)

	return p
}

func (p *Poly[F]) Multiply[FE curve.BasicField[F]](s *F) *Poly[F] {
	for i := range p.YCoefficients {
		FE(&p.YCoefficients[i]).Multiply(&p.YCoefficients[i], s)
	}
	for i := range p.YXCoefficients {
		for j := range p.YXCoefficients[i] {
			FE(&p.YXCoefficients[i][j]).Multiply(&p.YXCoefficients[i][j], s)
		}
	}
	for i := range p.XCoefficients {
		FE(&p.XCoefficients[i]).Multiply(&p.XCoefficients[i], s)
	}

	FE(&p.ZeroCoefficient).Multiply(&p.ZeroCoefficient, s)

	return p
}

func (p *Poly[F]) Negate[FE curve.BasicField[F]]() *Poly[F] {
	for i := range p.YCoefficients {
		FE(&p.YCoefficients[i]).Negate(&p.YCoefficients[i])
	}

	for i := range p.YXCoefficients {
		for j := range p.YXCoefficients[i] {
			FE(&p.YXCoefficients[i][j]).Negate(&p.YXCoefficients[i][j])
		}
	}

	for i := range p.XCoefficients {
		FE(&p.XCoefficients[i]).Negate(&p.XCoefficients[i])
	}

	FE(&p.ZeroCoefficient).Negate(&p.ZeroCoefficient)

	return p
}

func (p *Poly[F]) ShiftByX[FE curve.BasicField[F]](powerOfX int) *Poly[F] {
	if powerOfX == 0 {
		return p
	}
	// Shift up every x coefficient
	for range powerOfX {
		//TODO: more efficient insert/creation in one go
		p.XCoefficients = slices.Insert(p.XCoefficients, 0, *FE(new(F)).Zero())
		for i := range p.YXCoefficients {
			p.YXCoefficients[i] = slices.Insert(p.YXCoefficients[i], 0, *FE(new(F)).Zero())
		}
	}

	// Move the zero coefficient
	FE(&p.XCoefficients[powerOfX-1]).Set(&p.ZeroCoefficient)
	FE(&p.ZeroCoefficient).Zero()

	// Move the y coefficients

	// Now, ensure the yx coefficients has the slots for the y coefficients we're moving
	for len(p.YXCoefficients) < len(p.YCoefficients) {
		p.YXCoefficients = append(p.YXCoefficients, make([]F, powerOfX))
	}

	// Perform the move
	for i := range p.YCoefficients {
		FE(&p.YXCoefficients[i][powerOfX-1]).Set(&p.YCoefficients[i])
	}
	// clear
	p.YCoefficients = p.YCoefficients[:0]

	return p
}

func (p *Poly[F]) ShiftByY[FE curve.BasicField[F]](powerOfY int) *Poly[F] {
	if powerOfY == 0 {
		return p
	}

	// Shift up every y coefficient
	for range powerOfY {
		//TODO: more efficient insert/creation in one go
		p.YCoefficients = slices.Insert(p.YCoefficients, 0, *FE(new(F)).Zero())
		p.YXCoefficients = slices.Insert(p.YXCoefficients, 0, nil)
	}

	// Move the zero coefficient
	FE(&p.YCoefficients[powerOfY-1]).Set(&p.ZeroCoefficient)
	FE(&p.ZeroCoefficient).Zero()

	// Move the x coefficients
	p.YXCoefficients[powerOfY-1] = p.XCoefficients
	p.XCoefficients = nil

	return p
}

func (p *Poly[F]) MultiplyPoly[FE curve.BasicField[F]](o *Poly[F]) *Poly[F] {
	orig := p.Clone()
	p.Multiply[FE](&o.ZeroCoefficient)

	for i := range o.YCoefficients {
		scaled := orig.Clone().Multiply[FE](&o.YCoefficients[i])
		p.Add[FE](scaled.ShiftByY[FE](i + 1))
	}

	for y_i, yxCoeffs := range o.YXCoefficients {
		for x_i, yxCoeff := range yxCoeffs {
			scaled := orig.Clone().Multiply[FE](&yxCoeff)
			p.Add[FE](scaled.ShiftByY[FE](y_i + 1).ShiftByX[FE](x_i + 1))
		}
	}
	for i := range o.XCoefficients {
		scaled := orig.Clone().Multiply[FE](&o.XCoefficients[i])
		p.Add[FE](scaled.ShiftByX[FE](i + 1))
	}

	return p
}

func (p *Poly[F]) LeadingCoefficient() (y, x int) {
	if len(p.YCoefficients) > len(p.YXCoefficients) {
		return len(p.YCoefficients), 0
	} else if len(p.YXCoefficients) > 0 {
		return len(p.YXCoefficients), len(p.YXCoefficients[len(p.YXCoefficients)-1])
	} else {
		return 0, len(p.XCoefficients)
	}
}

func (p *Poly[F]) GreaterThanOrEqualCoefficient[FE curve.Field[F]](gteq *CoefficientIndex) CoefficientIndex {
	var leading CoefficientIndex

	for yPowSubOne, coeff := range p.YCoefficients {
		yPow := uint64(yPowSubOne + 1)
		coeffIsNonZero := 1 - FE(&coeff).IsZero()
		potential := CoefficientIndex{YPow: yPow}
		leading.Select(&potential, &leading, coeffIsNonZero&potential.Greater(&leading)&(potential.Greater(gteq)|potential.Equal(gteq)))
	}

	for yPowSubOne, yxCoefficients := range p.YXCoefficients {
		yPow := uint64(yPowSubOne + 1)
		for xPowSubOne, coeff := range yxCoefficients {
			xPow := uint64(xPowSubOne + 1)
			coeffIsNonZero := 1 - FE(&coeff).IsZero()
			potential := CoefficientIndex{YPow: yPow, XPow: xPow}
			leading.Select(&potential, &leading, coeffIsNonZero&potential.Greater(&leading)&(potential.Greater(gteq)|potential.Equal(gteq)))
		}
	}

	for xPowSubOne, coeff := range p.XCoefficients {
		xPow := uint64(xPowSubOne + 1)
		coeffIsNonZero := 1 - FE(&coeff).IsZero()
		potential := CoefficientIndex{XPow: xPow}
		leading.Select(&potential, &leading, coeffIsNonZero&potential.Greater(&leading)&(potential.Greater(gteq)|potential.Equal(gteq)))
	}

	return leading
}

func (p *Poly[F]) MultiplyPolyMod[FE curve.Field[F]](o, modulus *Poly[F]) *Poly[F] {
	_, rem := p.MultiplyPoly[FE](o).DividePoly[FE](modulus)
	return p.Set(rem)
}

func (p *Poly[F]) constGet[FE curve.BasicField[F]](index CoefficientIndex) *F {
	res := p.ZeroCoefficient
	for yPowSubOne := range p.YCoefficients {
		FE(&res).Select(&p.YCoefficients[yPowSubOne], &res, index.Equal(&CoefficientIndex{YPow: uint64(yPowSubOne + 1)}))
	}
	for yPowSubOne, yxCoefficients := range p.YXCoefficients {
		for xPowSubOne := range yxCoefficients {
			FE(&res).Select(&yxCoefficients[xPowSubOne], &res, index.Equal(&CoefficientIndex{YPow: uint64(yPowSubOne + 1), XPow: uint64(xPowSubOne + 1)}))
		}
	}
	for xPowSubOne := range p.XCoefficients {
		FE(&res).Select(&p.XCoefficients[xPowSubOne], &res, index.Equal(&CoefficientIndex{XPow: uint64(xPowSubOne + 1)}))
	}
	return &res
}

func (p *Poly[F]) constSet[FE curve.BasicField[F]](index *CoefficientIndex, v *F) {
	for yPowSubOne := range p.YCoefficients {
		FE(&p.YCoefficients[yPowSubOne]).Select(v, &p.YCoefficients[yPowSubOne], index.Equal(&CoefficientIndex{YPow: uint64(yPowSubOne + 1)}))
	}
	for yPowSubOne, yxCoefficients := range p.YXCoefficients {
		for xPowSubOne := range yxCoefficients {
			FE(&yxCoefficients[xPowSubOne]).Select(v, &yxCoefficients[xPowSubOne], index.Equal(&CoefficientIndex{YPow: uint64(yPowSubOne + 1), XPow: uint64(xPowSubOne + 1)}))
		}
	}
	for xPowSubOne := range p.XCoefficients {
		FE(&p.XCoefficients[xPowSubOne]).Select(v, &p.XCoefficients[xPowSubOne], index.Equal(&CoefficientIndex{XPow: uint64(xPowSubOne + 1)}))
	}
	FE(&p.ZeroCoefficient).Select(v, &p.ZeroCoefficient, index.Equal(&CoefficientIndex{}))
}

// Select sets p to a if cond == 1, and to b if cond == 0.
func (p *Poly[F]) Select[FE curve.BasicField[F]](a, b *Poly[F], cond int) *Poly[F] {
	a = a.Clone()
	b = b.Clone()

	// Pad these to be the same size/layout as each other
	a.pad[FE](b)
	b.pad[FE](a)

	p.Zero()

	var tmp F
	for i := range a.YCoefficients {
		p.YCoefficients = append(p.YCoefficients, *FE(&tmp).Select(&a.YCoefficients[i], &b.YCoefficients[i], cond))
	}

	p.YXCoefficients = slices.Grow(p.YXCoefficients, len(a.YXCoefficients))[:len(a.YXCoefficients)]
	for i := range a.YXCoefficients {
		p.YXCoefficients[i] = slices.Grow(p.YXCoefficients[i], len(a.YXCoefficients[i]))[:0]
		for j := range a.YXCoefficients[i] {
			p.YXCoefficients[i] = append(p.YXCoefficients[i], *FE(&tmp).Select(&a.YXCoefficients[i][j], &b.YXCoefficients[i][j], cond))
		}
	}
	for i := range a.XCoefficients {
		p.XCoefficients = append(p.XCoefficients, *FE(&tmp).Select(&a.XCoefficients[i], &b.XCoefficients[i], cond))
	}
	FE(&p.ZeroCoefficient).Select(&a.ZeroCoefficient, &b.ZeroCoefficient, cond)

	return p
}

func (p *Poly[F]) DividePoly[FE curve.Field[F]](denominator *Poly[F]) (quo, rem *Poly[F]) {
	// The following long division algorithm only works if the denominator actually has a variable
	// If the denominator isn't variable to anything, short-circuit to scalar 'division'
	// This is safe as `leading_coefficient` is based on the structure, not the values, of the poly

	denominatorLeadingCoefficientY, denominatorLeadingCoefficientX := denominator.LeadingCoefficient()
	if denominatorLeadingCoefficientX == 0 && denominatorLeadingCoefficientY == 0 {
		return p.Multiply[FE](FE(new(F)).Invert(&denominator.ZeroCoefficient)), &Poly[F]{}
	}

	// The structure of the quotient, which is the numerator with all coefficients set to 0
	yxClone := make([][]F, len(p.YXCoefficients))
	for i := range p.YXCoefficients {
		yxClone[i] = make([]F, len(p.YXCoefficients[i]))
	}
	quotientStructure := &Poly[F]{
		YCoefficients:  make([]F, len(p.YCoefficients)),
		YXCoefficients: yxClone,
		XCoefficients:  make([]F, len(p.XCoefficients)),
	}

	// Calculate the amount of iterations we need to perform
	iterations := len(p.YCoefficients) + len(p.XCoefficients)
	for i := range p.YXCoefficients {
		iterations += len(p.YXCoefficients[i])
	}

	// Find the highest non-zero coefficient in the denominator
	// This is the coefficient which we actually perform division with
	denominatorDividingCoefficient := denominator.GreaterThanOrEqualCoefficient[FE](&CoefficientIndex{})

	denominatorDividingCoefficientInv := FE(new(F)).Invert(denominator.constGet[FE](denominatorDividingCoefficient))

	quo = quotientStructure.Clone()
	rem = p.Clone()

	for range iterations {
		// Find the numerator coefficient we're clearing
		// This will be (0, 0) if we aren't clearing a coefficient
		numeratorCoefficient := rem.GreaterThanOrEqualCoefficient[FE](&denominatorDividingCoefficient)

		// We only apply the effects of this iteration if the numerator's coefficient is actually >=
		meaningfulIteration := numeratorCoefficient.Greater(&denominatorDividingCoefficient) | numeratorCoefficient.Equal(&denominatorDividingCoefficient)

		// 1) Find the scalar `q` such that the leading coefficient of `q * denominator` is equal to
		//    the leading coefficient of self.
		numeratorCoefficientValue := rem.constGet[FE](numeratorCoefficient)
		q := FE(new(F)).Multiply(numeratorCoefficientValue, denominatorDividingCoefficientInv)

		// 2) Calculate the full term of the quotient by scaling with the necessary powers of y/x
		properPowersOfYX := CoefficientIndex{
			YPow: numeratorCoefficient.YPow - denominatorDividingCoefficient.YPow,
			XPow: numeratorCoefficient.XPow - denominatorDividingCoefficient.XPow,
		}

		fallbackPowersOfYX := CoefficientIndex{}
		quotientTerm := quotientStructure.Clone()
		// If the numerator coefficient isn't >=, proper_powers_of_yx will have garbage in them
		quotientTerm.constSet[FE](new(CoefficientIndex).Select(&properPowersOfYX, &fallbackPowersOfYX, meaningfulIteration), q)

		quotientIfMeaningful := quo.Clone().Add[FE](quotientTerm)
		quo = quo.Select[FE](quotientIfMeaningful, quo, meaningfulIteration)

		// 3) Remove what we've divided out from self
		remainderIfMeaningful := rem.Clone().Subtract[FE](quotientTerm.MultiplyPoly[FE](denominator))
		rem = rem.Select[FE](remainderIfMeaningful, rem, meaningfulIteration)
	}

	// If the dividing coefficient was for y**0 x**0, we return the poly scaled by its inverse
	quo = quo.Select[FE](p.Clone().Multiply[FE](denominatorDividingCoefficientInv), quo, denominatorDividingCoefficient.Equal(&CoefficientIndex{}))
	// If the dividing coefficient was for y**0 x**0, we're able to perfectly divide and there's no remainder
	rem = rem.Select[FE](new(Poly[F]), rem, denominatorDividingCoefficient.Equal(&CoefficientIndex{}))

	// Clear any junk terms out of the remainder which are less than the denominator

	denominatorLeadingCoefficient := CoefficientIndex{
		YPow: uint64(denominatorLeadingCoefficientY),
		XPow: uint64(denominatorLeadingCoefficientX),
	}

	if denominatorLeadingCoefficient.Equal(&CoefficientIndex{}) == 0 {
		for {
			index := CoefficientIndex{YPow: uint64(len(rem.YCoefficients)), XPow: 0}
			if (index.Greater(&denominatorLeadingCoefficient) | index.Equal(&denominatorLeadingCoefficient)) == 0 {
				break
			}
			rem.YCoefficients = rem.YCoefficients[:len(rem.YCoefficients)-1]
		}

		for {
			var lastLen int
			if len(rem.YXCoefficients) > 0 {
				lastLen = len(rem.YXCoefficients[len(rem.YXCoefficients)-1])
			}
			index := CoefficientIndex{YPow: uint64(len(rem.YXCoefficients)), XPow: uint64(lastLen)}
			if (index.Greater(&denominatorLeadingCoefficient) | index.Equal(&denominatorLeadingCoefficient)) == 0 {
				break
			}
			last := &rem.YXCoefficients[len(rem.YXCoefficients)-1]
			if len(*last) > 0 {
				*last = (*last)[:len(*last)-1]
			}
			if len(*last) == 0 {
				rem.YXCoefficients = rem.YXCoefficients[:len(rem.YXCoefficients)-1]
			}
		}

		for {
			index := CoefficientIndex{YPow: 0, XPow: uint64(len(rem.XCoefficients))}
			if (index.Greater(&denominatorLeadingCoefficient) | index.Equal(&denominatorLeadingCoefficient)) == 0 {
				break
			}
			rem.XCoefficients = rem.XCoefficients[:len(rem.XCoefficients)-1]
		}

	}

	return quo, rem
}

// Eval Evaluate this polynomial with the specified x/y values.
func (p *Poly[F]) Eval[FE curve.Field[F]](out, x, y *F) *F {
	FE(out).Set(&p.ZeroCoefficient)
	var buf [8]byte
	var tmp F
	for i := range p.YCoefficients {
		binary.LittleEndian.PutUint64(buf[:], uint64(i+1))
		FE(out).Add(out, FE(&tmp).Multiply(curve.FieldPow[F, FE](&tmp, y, buf[:]), &p.YCoefficients[i]))
	}
	for i := range p.YXCoefficients {
		binary.LittleEndian.PutUint64(buf[:], uint64(i+1))
		yPow := curve.FieldPow[F, FE](new(F), y, buf[:])
		for j := range p.YXCoefficients[i] {
			binary.LittleEndian.PutUint64(buf[:], uint64(j+1))
			FE(out).Add(out, FE(&tmp).Multiply(yPow, FE(&tmp).Multiply(curve.FieldPow[F, FE](&tmp, x, buf[:]), &p.YXCoefficients[i][j])))
		}
	}
	for i := range p.XCoefficients {
		binary.LittleEndian.PutUint64(buf[:], uint64(i+1))
		FE(out).Add(out, FE(&tmp).Multiply(curve.FieldPow[F, FE](&tmp, x, buf[:]), &p.XCoefficients[i]))
	}

	return out
}

func (p *Poly[F]) NormalizeXCoefficient[FE curve.BasicField[F]]() *Poly[F] {
	scalar := FE(new(F)).Invert(&p.XCoefficients[0])
	return p.Multiply[FE](scalar)
}

// Differentiate a polynomial, reduced by a modulus with a leading y term y^2 x^0, by x and y.
func (p *Poly[F]) Differentiate[FE curve.Field[F]]() (*Poly[F], *Poly[F]) {
	// Differentation by x practically involves:
	// - Dropping everything without an x component
	// - Shifting everything down a power of x
	// - Multiplying the new coefficient by the power it prior was used with

	var one F
	FE(&one).One()

	var diffX Poly[F]
	if len(p.XCoefficients) != 0 {
		xCoeffs := slices.Clone(p.XCoefficients)
		diffX.ZeroCoefficient = xCoeffs[0]
		xCoeffs = xCoeffs[1:]
		diffX.XCoefficients = xCoeffs

		// priorXPower = 2
		priorXPower := FE(new(F)).Add(&one, &one)
		for i := range diffX.XCoefficients {
			FE(&diffX.XCoefficients[i]).Multiply(&diffX.XCoefficients[i], priorXPower)
			FE(priorXPower).Add(priorXPower, &one)
		}
	}

	if len(p.YCoefficients) != 0 {
		yxCoeffs := slices.Clone(p.YXCoefficients[0])
		if len(yxCoeffs) != 0 {
			diffX.YCoefficients = []F{yxCoeffs[0]}
			diffX.YXCoefficients = [][]F{yxCoeffs[1:]}

			// priorXPower = 2
			priorXPower := FE(new(F)).Add(&one, &one)
			for i := range diffX.YXCoefficients[0] {
				FE(&diffX.YXCoefficients[0][i]).Multiply(&diffX.YXCoefficients[0][i], priorXPower)
				FE(priorXPower).Add(priorXPower, &one)
			}
		}
	}

	var zeroCoeff F
	if len(p.YCoefficients) > 0 {
		zeroCoeff = p.YCoefficients[0]
	}
	// Differentation by y is trivial
	// It's the y coefficient as the zero coefficient, and the yx coefficients as the x
	// coefficients
	// This is thanks to any y term over y^2 being reduced out
	diffY := Poly[F]{
		XCoefficients:   slices.Clone(p.YXCoefficients[0]),
		ZeroCoefficient: zeroCoeff,
	}

	return &diffX, &diffY
}

// ScalarMultDivisor A divisor to prove a scalar multiplication.
//
// The divisor will interpolate $-(s \cdot G)$ with $d_i$ instances of $2^i \cdot G$.
//
// This function executes in constant time with regards to the scalar.
func (p *Poly[F]) ScalarMultDivisor[C DivisorCurve[curve.Ciphersuite[P, F], P, F], XY any, P any, FE curve.Field[F], PE curve.CurvePoint[P, F], XYE XyPointExtra[XY, P, F, FE]](s *ScalarDecomposition[F], generator *P) *Poly[F] {
	// 1 is used for the resulting point, NUM_BITS is used for the decomposition, and then we store
	// one additional index in a usize for the points we shouldn't write at all (hence the +2)
	numBits := FE(new(F)).NumBits()
	divisorPoints := make([]XY, numBits+1)
	for i := range divisorPoints {
		XYE(&divisorPoints[i]).Identity()
	}

	// Write the inverse of the resulting point
	XYE(&divisorPoints[0]).From(PE(new(P)).ScalarMult(&s.Scalar, PE(new(P)).Negate(generator)))

	{
		generator := XYE(new(XY)).From(generator)

		// Write the decomposition
		var writeAbove uint64
		for _, coefficient := range s.Decomposition {
			// Write the generator to every slot except the slots we have already written to.
			for i := 1; i <= numBits; {
				XYE(&divisorPoints[i]).Select(generator, &divisorPoints[i], greater64Bits(uint64(i), writeAbove))
			}

			// Increase the next write start by the coefficient.
			writeAbove += coefficient
			XYE(generator).Double(generator)
		}

		var c C

		// Create a divisor out of the points
		return NewDivisor[C, P, F, XY, FE, XYE](divisorPoints, c.InterpolatorForScalarMul())
	}
}
