package ec_gadgets

import gp "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"

// CurveSpec The specification of a short Weierstrass curve over the field `F`.
//
// The short Weierstrass curve is defined via the formula `y**2 = x**3 + a*x + b`.
type CurveSpec[F any] struct {
	// A The a constant in the curve formula
	A F
	// B The b constant in the curve formula
	B F
}

// OnCurve A struct for a point on a towered curve which has been confirmed to be on-curve.
type OnCurve struct {
	X gp.Variable
	Y gp.Variable
}

type EcGadgets[F any] interface {
	// OnCurve Constrain an x and y coordinate as being on the specified curve.
	//
	// The specified curve is defined over the scalar field of the curve this proof is performed
	// over, offering efficient arithmetic.
	//
	// May panic if the prover and the point is not actually on-curve.
	OnCurve(curve *CurveSpec[F], point [2]gp.Variable) OnCurve

	// IncompleteAddFixed Perform incomplete addition for a fixed point and an on-curve point.
	//
	// `a` is the x and y coordinates of the fixed point, assumed to be on-curve.
	//
	// `b` is a point prior checked to be on-curve.
	//
	// `c` is a point prior checked to be on-curve, constrained to be the sum of `a` and `b`.
	//
	// `a` and `b` are checked to have distinct x coordinates.
	//
	// This function may panic if `a` is malformed or if the prover and `c` is not actually the sum
	// of `a` and `b`.
	IncompleteAddFixed(a [2]F, b, c OnCurve) OnCurve
}
