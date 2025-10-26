package curve25519

import (
	"git.gammaspectra.live/P2Pool/edwards25519/field"
)

// Elligator2WithUniformBytes
// Equivalent to ge_fromfe_frombytes_vartime
// constant time
func Elligator2WithUniformBytes[T PointOperations, S ~[PublicKeySize]byte](dst *PublicKey[T], buf S) *PublicKey[T] {
	/*
	   Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

	   A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
	   `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
	*/

	// Convert the uniform bytes to a FieldElement
	/*
	   This isn't a wide reduction, implying it'd be biased, yet the bias should only be negligible
	   due to the shape of the prime number. All elements within the prime field field have a
	   `2 / 2^{256}` chance of being selected, except for the first 19 which have a `3 / 2^256`
	   chance of being selected. In order for this 'third chance' (the bias) to be relevant, the
	   hash function would have to output a number greater than or equal to:

	     0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda

	   which is of negligible probability.
	*/

	var r, o, tmp1, tmp2, tmp3 field.Element
	_, _ = r.SetBytesPropagate(buf[:])

	// Per Section 5.5, take `u = 2`. This is the smallest quadratic non-residue in the field
	urSquare := r.Square(&r)
	urSquareDouble := urSquare.Add(urSquare, urSquare)

	/*
	   We know this is non-zero as:

	   ```sage
	   p = 2**255 - 19
	   Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
	   ```
	*/
	onePlusUrSquare := urSquareDouble.Add(_ONE, urSquareDouble)
	onePlusUrSquareInverted := onePlusUrSquare.Invert(onePlusUrSquare)

	upsilon := onePlusUrSquareInverted.Multiply(_NEGATIVE_A, onePlusUrSquareInverted)

	/*
	   Quoting section 5.5,
	   "then \epsilon = 1 and x = \upsilon. Otherwise \epsilon = -1, x = \upsilon u r^2"

	   Whereas in the specification present in Section 5.2, the expansion of the `u` coordinate when
	   `\epsilon = -1` is `-\upsilon - A`. Per Section 5.2, in the "Second case",
	   `= -\upsilon - A = \upsilon u r^2`. These two values are equivalent, yet the negation and
	   subtract outperform a multiplication.
	*/
	otherCandidate := o.Subtract(tmp1.Negate(upsilon), _A)

	/*
	   Check if `\upsilon` is a valid `u` coordinate by checking for a solution for the square root
	   of `\upsilon^3 + A \upsilon^2 + \upsilon`.
	*/
	// TODO: replace this with field.Element.Sqrt
	_, epsilon := tmp3.SqrtRatio(
		tmp3.Add(
			tmp3.Multiply(
				tmp1.Add(upsilon, _A),
				tmp2.Square(upsilon),
			),
			upsilon,
		),
		_ONE,
	)

	// select upsilon when epsilon is 1 (isSquare)
	u := r.Select(upsilon, otherCandidate, epsilon)

	// Map from Curve25519 to Ed25519
	/*
	   Elligator 2's specification in section 5.2 says to choose the negative square root as the
	   `v` coordinate if `\upsilon` was chosen (as signaled by `\epsilon = 1`). The following
	   chooses the odd `y` coordinate if `\upsilon` was chosen, which is functionally equivalent.
	*/
	return DecodeMontgomeryPoint(dst, u, epsilon)
}
