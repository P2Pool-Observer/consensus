package divisors

import (
	"crypto/subtle"
	"iter"
	"reflect"
	"slices"
	"sync"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519/field"
)

type DivisorCurve[C curve.Ciphersuite[P, F], P any, F any] interface {
	curve.Ciphersuite[P, F]

	InterpolatorForScalarMul() *Interpolator[F]
	InterpolatorForScalarMulDegree() int
}

type DivisorCurveCiphersuite[P any, F any] interface {
	curve.Ciphersuite[P, F]

	InterpolatorForScalarMulDegree() int
}

type Edwards25519DivisorCiphersuite = DivisorCiphersuite[curve25519.Ciphersuite, curve25519.Point, field.Element, *field.Element]

type DivisorCiphersuite[C DivisorCurveCiphersuite[P, F], P any, F any, FE curve.Field[F]] struct{}

func (c DivisorCiphersuite[C, P, F, FE]) c() C {
	var zero C
	return zero
}

func (c DivisorCiphersuite[C, P, F, FE]) A() *F {
	return c.c().A()
}

func (c DivisorCiphersuite[C, P, F, FE]) B() *F {
	return c.c().B()
}

func (c DivisorCiphersuite[C, P, F, FE]) Generator() *P {
	return c.c().Generator()
}

func (c DivisorCiphersuite[C, P, F, FE]) ScalarBits() int {
	return c.c().ScalarBits()
}

var interpolatorCacheRWLock sync.RWMutex
var interpolatorCache = make(map[string]any)

func (c DivisorCiphersuite[C, P, F, FE]) InterpolatorForScalarMul() *Interpolator[F] {
	//TODO: find a better way to generate and key this
	key := utils.SprintfNoEscape("%s.%s#%d", reflect.TypeFor[F]().PkgPath(), reflect.TypeFor[F]().Name(), c.InterpolatorForScalarMulDegree())

	if i := func() *Interpolator[F] {
		interpolatorCacheRWLock.RLock()
		defer interpolatorCacheRWLock.RUnlock()
		v, ok := interpolatorCache[key]
		if !ok {
			return nil
		}
		if i, ok := v.(*Interpolator[F]); !ok {
			return nil
		} else {
			return i
		}
	}(); i != nil {
		return i
	}

	// generate
	i := NewInterpolator[F, FE](c.InterpolatorForScalarMulDegree())

	// lock. this may race, but it's ok, just some wasted cpu
	interpolatorCacheRWLock.Lock()
	defer interpolatorCacheRWLock.Unlock()
	interpolatorCache[key] = &i
	return &i
}

func (c DivisorCiphersuite[C, P, F, FE]) InterpolatorForScalarMulDegree() int {
	return c.c().InterpolatorForScalarMulDegree()
}

func (c DivisorCiphersuite[C, P, F, FE]) XY(v *P) (x, y F, err error) {
	return c.c().XY(v)
}

type XyPoint[XY any] interface {
	*XY

	IsIdentity() int
	Equal(x *XY) int
	Select(a, b *XY, cond int) *XY
	Identity()
	Negate(x *XY) *XY
	Add(a, b *XY) *XY
	Double(x *XY) *XY
}

type XyPointBatchXY[XY any, F any, FE curve.BasicField[F]] interface {
	XyPoint[XY]

	BatchXY(points []XY, out []Xy[F]) *XY
}

type XyPointExtra[XY any, P any, F any, FE curve.BasicField[F]] interface {
	XyPoint[XY]
	XyPointBatchXY[XY, F, FE]

	From(x *P) *XY
}

type LineArgs[F any, XY any] struct {
	B                               XY
	BothAreIdentity                 int
	OneIsIdentityOrAdditiveInverses int
	ConstantTerm                    F
}

func NewLineArgs[F any, XY any, FE curve.BasicField[F], XYE XyPoint[XY]](a, b *XY, aX, bX *F, gen *XY) LineArgs[F, XY] {
	aIsIdentity := XYE(a).IsIdentity()
	bIsIdentity := XYE(b).IsIdentity()

	bothAreIdentity := aIsIdentity & bIsIdentity

	oneIsIdentity := aIsIdentity | bIsIdentity
	additiveInverses := XYE(a).Equal(XYE(new(XY)).Negate(b))

	oneIsIdentityOrAdditiveInverses := oneIsIdentity | additiveInverses
	constantTerm := FE(new(F)).Select(bX, aX, aIsIdentity)

	a = XYE(new(XY)).Select(gen, a, aIsIdentity)
	b = XYE(new(XY)).Select(gen, b, bIsIdentity)
	XYE(b).Select(XYE(new(XY)).Double(a), b, additiveInverses)
	XYE(b).Select(XYE(new(XY)).Negate(XYE(new(XY)).Double(a)), b, XYE(a).Equal(b))

	return LineArgs[F, XY]{
		B:                               *b,
		BothAreIdentity:                 bothAreIdentity,
		OneIsIdentityOrAdditiveInverses: oneIsIdentityOrAdditiveInverses,
		ConstantTerm:                    *constantTerm,
	}
}

type Xy[F any] = [2]F

// SlopesAndIntercepts Computes all (slope, intercept) pairs, batching inverses.
func SlopesAndIntercepts[F any, XY any, FE curve.BasicField[F], XYE XyPointBatchXY[XY, F, FE]](a []Xy[F], b []XY) (result [][2]F) {
	bXY := make([]Xy[F], len(b))
	XYE(new(XY)).BatchXY(b, bXY)

	diffs := make([]F, len(b))
	for i := range a {
		ax := &a[i][0]
		bx := &bXY[i][0]
		FE(&diffs[i]).Subtract(bx, ax)
	}

	curve.BatchInvert[F, FE](new(F), utils.ValuesToPointers(diffs)...)

	result = make([][2]F, 0, len(diffs))

	for i := range a {
		_, ay := &a[i][0], &a[i][1]
		bx, by := &bXY[i][0], &bXY[i][1]

		slope := FE(new(F)).Multiply(FE(new(F)).Subtract(by, ay), &diffs[i])
		intercept := FE(new(F)).Subtract(by, FE(new(F)).Multiply(slope, bx))
		//TODO: debug assert
		result = append(result, [2]F{*slope, *intercept})
	}

	return result
}

// FinishLine Complete calculation of a line from its arguments and the (potentitally stubbed) slope/intercept.
func FinishLine[F any, FE curve.BasicField[F]](slope, intercept *F, bothAreIdentity int, oneIsIdentityOrAdditiveInverses int, constantTerm *F) *SmallDivisor[F] {
	// y - slope x - intercept
	res := &SmallDivisor[F]{
		XCoefficient:    *FE(new(F)).Negate(slope),
		ZeroCoefficient: *FE(new(F)).Negate(intercept),
		YCoefficient:    *FE(new(F)).One(),
	}

	// `x - x`, where the first `x` is the coefficient and the second `x` is a constant of the `x`
	// coordinate present within this pair of points
	res.Select[FE](&SmallDivisor[F]{
		XCoefficient:    *FE(new(F)).One(),
		ZeroCoefficient: *FE(new(F)).Negate(constantTerm),
		YCoefficient:    *FE(new(F)).Zero(),
	}, res, oneIsIdentityOrAdditiveInverses)

	// 1
	return res.Select[FE](&SmallDivisor[F]{
		XCoefficient:    *FE(new(F)).Zero(),
		ZeroCoefficient: *FE(new(F)).One(),
		YCoefficient:    *FE(new(F)).Zero(),
	}, res, bothAreIdentity)
}

type LineAndDenom[F any, FE curve.BasicField[F]] struct {
	D     SmallDivisor[F]
	Denom [2]utils.ConstantOption[F, FE]
}

func LinesAndDenoms[C DivisorCurve[curve.Ciphersuite[P, F], P, F], XYE XyPointExtra[XY, P, F, FE], P any, F any, XY any, FE curve.BasicField[F]](points []XY) (result []LineAndDenom[F, FE]) {
	pairs := make([][2]XY, 0, len(points))
	{
		// All the pairs of points from which lines will be created
		divs := make([]XY, 0, utils.DivCeil(len(points), 2))

		next, stop := iter.Pull(slices.Values(points))
		defer stop()
		for a, ok := next(); ok; {
			b, ok := next()
			if !ok {
				XYE(&b).Identity()
				divs = append(divs, a)
			} else {
				divs = append(divs, *XYE(new(XY)).Add(&a, &b))
			}
			pairs = append(pairs, [2]XY{a, b})
		}

		for len(divs) > 1 {
			nextDivs := make([]XY, 0, len(divs)/2+1)
			// If there's an odd amount of divisors, carry the odd one out to the next iteration
			if len(divs)%2 == 1 {
				nextDivs = append(nextDivs, divs[len(divs)-1])
				divs = divs[:len(divs)-1]
			}

			for len(divs) > 0 {
				a := divs[len(divs)-1]
				b := divs[len(divs)-2]
				divs = divs[:len(divs)-2]
				pairs = append(pairs, [2]XY{a, b})
				nextDivs = append(nextDivs, *XYE(new(XY)).Add(&a, &b))
			}
			divs = nextDivs
		}
	}

	var c C

	gen := XYE(new(XY)).From(c.Generator())

	var aXY, bXY []Xy[F]
	{
		a := len(pairs)
		points := make([]XY, a*2)
		for i := range pairs {
			XYE(&points[i]).Select(gen, &pairs[i][0], XYE(&pairs[i][0]).IsIdentity())
			XYE(&points[i+a]).Select(gen, &pairs[i][1], XYE(&pairs[i][1]).IsIdentity())
		}
		xy := make([]Xy[F], a*2)
		XYE(new(XY)).BatchXY(points, xy)
		aXY = xy[:a:a]
		bXY = xy[a:]
	}

	lineArgs := make([]LineArgs[F, XY], 0, len(pairs))
	denoms := make([][2]utils.ConstantOption[F, FE], 0, len(pairs))
	b := make([]XY, 0, len(pairs))

	{
		for i := range pairs {
			aX := &aXY[i][0]
			bX := &bXY[i][0]

			denom := [2]utils.ConstantOption[F, FE]{
				*utils.MakeConstantOption[F, FE](*aX, 1-XYE(&pairs[i][0]).IsIdentity()),
				*utils.MakeConstantOption[F, FE](*bX, 1-XYE(&pairs[i][1]).IsIdentity()),
			}

			args := NewLineArgs[F, XY, FE, XYE](&pairs[i][0], &pairs[i][1], aX, bX, gen)

			lineArgs = append(lineArgs, args)
			b = append(b, args.B)
			denoms = append(denoms, denom)
		}
	}

	slopesAndIntercepts := SlopesAndIntercepts[F, XY, FE, XYE](aXY, b)

	result = make([]LineAndDenom[F, FE], 0, len(lineArgs))
	for i := range lineArgs {
		line := FinishLine[F, FE](&slopesAndIntercepts[i][0], &slopesAndIntercepts[i][1], lineArgs[i].BothAreIdentity, lineArgs[i].OneIsIdentityOrAdditiveInverses, &lineArgs[i].ConstantTerm)
		result[i] = LineAndDenom[F, FE]{
			D:     *line,
			Denom: denoms[i],
		}
	}
	return result
}

// DivisorToPoly Convert divisor from univariate to bivariate representation.
func DivisorToPoly[F any, FE curve.BasicField[F]](divisor *Divisor[F], interpolator *Interpolator[F]) *Poly[F] {
	a, b := divisor.Interpolate[FE](interpolator)

	zeroCoefficient := a[0]
	xCoefficients := a[1:]
	yxCoefficients := [][]F{b[1:]}
	yCoefficients := []F{b[0]}

	return &Poly[F]{
		ZeroCoefficient: zeroCoefficient,
		XCoefficients:   xCoefficients,
		YXCoefficients:  yxCoefficients,
		YCoefficients:   yCoefficients,
	}
}

func NewDivisor[C DivisorCurve[curve.Ciphersuite[P, F], P, F], P any, F any, XY any, FE curve.Field[F], XYE XyPointExtra[XY, P, F, FE]](points []XY, interpolator *Interpolator[F]) *Poly[F] {
	// No points were passed in, this is the point at infinity, or the single point isn't infinity
	// and accordingly doesn't sum to infinity. All three cause us to return None
	// Checks a bit other than the first bit is set, meaning this is >= 2
	invalidArgs := subtle.ConstantTimeEq(int32(len(points)&(^1)), 0)

	// The points don't sum to the point at infinity
	{
		var sum XY
		XYE(&sum).Identity()
		for i := range points {
			XYE(&sum).Add(&sum, &points[i])
		}

		invalidArgs |= 1 - XYE(&sum).IsIdentity()
	}

	// A point was the point at identity
	for i := range points {
		invalidArgs |= XYE(&points[i]).IsIdentity()
	}

	if invalidArgs != 0 {
		return nil
	}

	pointsLen := len(points)

	var c C

	modulus := ComputeModulus[F, FE](c.A(), c.B(), interpolator.RequiredEvaluations())
	// Create the initial set of divisors
	var divs []Divisor[F]
	allLines, stop := iter.Pull(slices.Values(LinesAndDenoms[C, XYE, P, F, XY, FE](points)))
	defer stop()
	for range pointsLen/2 + pointsLen%2 {
		line, ok := allLines()
		if !ok {
			panic("unsupported")
		}
		divs = append(divs, *NewDivisorFromSmall[F, FE](&line.D, modulus))
	}

	// Our Poly algorithm is leaky and will create an excessive amount of y x**j and x**j
	// coefficients which are zero, yet as our implementation is constant time, still come with
	// an immense performance cost. This code truncates the coefficients we know are zero.
	trim := func(divisor *Poly[F], pointsLen int) {
		// We should only be trimming divisors reduced by the modulus
		if len(divisor.YXCoefficients) > 1 {
			panic("unsupported")
		}
		if len(divisor.YXCoefficients) == 1 {
			truncateTo := max(0, utils.DivCeil(pointsLen, 2)-2)

			for p := truncateTo; p < len(divisor.YXCoefficients[0]); p++ {
				// TODO debug assert
				if FE(&divisor.YXCoefficients[0][p]).IsZero() == 0 {
					panic("unsupported")
				}
			}
			divisor.YXCoefficients[0] = divisor.YXCoefficients[0][:truncateTo]
		}
		{
			truncateTo := pointsLen / 2
			for p := truncateTo; p < len(divisor.XCoefficients); p++ {
				// TODO debug assert
				if FE(&divisor.XCoefficients[p]).IsZero() == 0 {
					panic("unsupported")
				}
			}
			divisor.XCoefficients = divisor.XCoefficients[:truncateTo]
		}
	}

	// Pair them off until only one remains
	for len(divs) > 1 {
		var nextDivs []Divisor[F]
		// If there's an odd amount of divisors, carry the odd one out to the next iteration
		if len(divs)%2 == 1 {
			nextDivs = append(nextDivs, divs[len(divs)-1])
			divs = divs[:len(divs)-1]
		}

		for len(divs) > 0 {
			a := divs[len(divs)-1]
			b := divs[len(divs)-2]
			divs = divs[:len(divs)-2]

			line, ok := allLines()
			if !ok {
				panic("unsupported")
			}

			merged := MergeDivisors[F, FE](&a, &b, &line.D, line.Denom[0], line.Denom[1], modulus)
			nextDivs = append(nextDivs, *merged)
		}

		divs = nextDivs
	}

	// Return the unified divisor
	divisor := DivisorToPoly[F, FE](&divs[0], interpolator)
	trim(divisor, pointsLen)
	return divisor
}
