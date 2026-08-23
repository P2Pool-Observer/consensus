package curve

// WeierstrassAffineDouble Double an affine point in projective short Weierstrass form
// mdbl-2007-bl https://eprint.iacr.org/2007/286
// cost: 3M + 5S + 7add + 4*2 + 1*3 + 1*4
// https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-mdbl-2007-bl
func WeierstrassAffineDouble[F any, FE Field[F]](outX, outY *F, a *F, x1, y1 *F) (x, y *F) {

	var tmp1, tmp2 F

	xx := FE(new(F)).Square(x1)
	// let w = a + (xx + xx.double());
	w := FE(new(F)).Add(a, FE(&tmp1).Add(xx, FE(&tmp2).Add(xx, xx)))
	y1y1 := FE(new(F)).Square(y1)
	r := FE(new(F)).Add(y1y1, y1y1)

	// let sss = (y1 * r).double().double();
	FE(&tmp1).Multiply(y1, r)
	FE(&tmp1).Add(&tmp1, &tmp1)
	sss := FE(new(F)).Add(&tmp1, &tmp1)
	rr := FE(new(F)).Square(r)

	// let b = x1 + r;
	// let b = (b * b) - xx - rr;
	b := FE(new(F)).Add(x1, r)
	FE(b).Square(b)
	FE(b).Subtract(b, xx)
	FE(b).Subtract(b, rr)

	// let h = (w * w) - b.double();
	h := FE(new(F)).Subtract(FE(&tmp1).Square(w), FE(&tmp2).Add(b, b))
	x3 := FE(new(F)).Multiply(FE(&tmp2).Add(h, h), y1)
	// let y3 = (w * (b - h)) - rr.double();
	y3 := FE(new(F)).Subtract(FE(&tmp1).Multiply(w, FE(&tmp1).Subtract(b, h)), FE(&tmp2).Add(rr, rr))
	z3 := sss

	// Normalize from XYZ to XY
	z3Inv := FE(new(F)).Invert(z3)
	if z3Inv == nil {
		panic("z3 cannot be inverted")
	}
	FE(outX).Multiply(x3, z3Inv)
	FE(outY).Multiply(y3, z3Inv)

	return outX, outY
}

// WeierstrassAffineIncompleteAdd Incomplete addition of affine points in projective short Weierstrass form
// mmadd-1998-cmo https://link.springer.com/chapter/10.1007/3-540-49649-1_6
// cost: 5M + 2S + 6add + 1*2
// https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-mmadd-1998-cmo
func WeierstrassAffineIncompleteAdd[F any, FE Field[F]](outX, outY *F, x1, y1, x2, y2 *F) (x, y *F) {
	if FE(x1).Equal(x2) == 1 {
		panic("equal x1 == x2")
	}

	u := FE(new(F)).Subtract(y2, y1)
	uu := FE(new(F)).Square(u)
	v := FE(new(F)).Subtract(x2, x1)
	vv := FE(new(F)).Square(v)
	vvv := FE(new(F)).Multiply(v, vv)
	r := FE(new(F)).Multiply(vv, x1)
	a := FE(new(F)).Subtract(uu, vvv)
	FE(a).Subtract(a, FE(new(F)).Add(r, r))
	x3 := FE(new(F)).Multiply(v, a)
	y3 := FE(new(F)).Multiply(u, FE(new(F)).Subtract(r, a))
	FE(y3).Subtract(y3, FE(new(F)).Multiply(vvv, y1))
	z3 := vvv

	// Normalize from XYZ to XY
	z3Inv := FE(new(F)).Invert(z3)
	if z3Inv == nil {
		panic("z3 cannot be inverted")
	}
	FE(outX).Multiply(x3, z3Inv)
	FE(outY).Multiply(y3, z3Inv)

	return outX, outY
}
