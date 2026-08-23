package divisors

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// Projective A point in projective coordinates.
type Projective[C curve.Ciphersuite[P, F], P any, F any, FE curve.Field[F]] struct {
	X, Y, Z F
}

func (p *Projective[C, P, F, FE]) Identity() *Projective[C, P, F, FE] {
	FE(&p.X).Zero()
	FE(&p.Y).One()
	FE(&p.Z).Zero()
	return p
}

func (p *Projective[C, P, F, FE]) IsIdentity() int {
	return FE(&p.Z).IsZero()
}

func (p *Projective[C, P, F, FE]) From(v *P) *Projective[C, P, F, FE] {
	var c C
	x, y, err := c.XY(v)
	if err != nil {
		return p.Identity()
	}

	FE(&p.X).Set(&x)
	FE(&p.Y).Set(&y)
	FE(&p.Z).One()
	return p
}

func (p *Projective[C, P, F, FE]) Equal(v *Projective[C, P, F, FE]) int {
	c1 := FE(FE(new(F)).Multiply(&p.X, &v.Z)).Equal(FE(new(F)).Multiply(&v.X, &p.Z))
	c2 := FE(FE(new(F)).Multiply(&p.Y, &v.Z)).Equal(FE(new(F)).Multiply(&v.Y, &p.Z))
	return c1 & c2
}

func (p *Projective[C, P, F, FE]) Negate(v *Projective[C, P, F, FE]) *Projective[C, P, F, FE] {
	p.X = v.X
	FE(&p.Y).Negate(&v.Y)
	p.Z = v.Z
	return p
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (p *Projective[C, P, F, FE]) Select(a, b *Projective[C, P, F, FE], cond int) *Projective[C, P, F, FE] {
	FE(&p.X).Select(&a.X, &b.X, cond)
	FE(&p.Y).Select(&a.Y, &b.Y, cond)
	FE(&p.Z).Select(&a.Z, &b.Z, cond)
	return p
}

func (p *Projective[C, P, F, FE]) Add(a, b *Projective[C, P, F, FE]) *Projective[C, P, F, FE] {
	// add-1998-cmo-2

	y1z2 := FE(new(F)).Multiply(&a.Y, &b.Z)
	x1z2 := FE(new(F)).Multiply(&a.X, &b.Z)
	z1z2 := FE(new(F)).Multiply(&a.Z, &b.Z)

	u := FE(new(F)).Multiply(&b.Y, &a.Z)
	FE(u).Subtract(u, y1z2)
	uu := FE(new(F)).Square(u)
	v := FE(new(F)).Multiply(&b.X, &a.Z)
	FE(v).Subtract(u, x1z2)
	vv := FE(new(F)).Square(v)
	vvv := FE(new(F)).Multiply(vv, v)
	R := FE(new(F)).Multiply(vv, x1z2)
	A := FE(new(F)).Multiply(uu, z1z2)
	FE(A).Subtract(A, vvv)
	FE(A).Subtract(A, FE(new(F)).Add(R, R))

	var res Projective[C, P, F, FE]
	FE(&res.X).Multiply(v, A)
	FE(&res.Y).Subtract(FE(new(F)).Multiply(u, FE(new(F)).Subtract(R, A)), FE(new(F)).Multiply(vvv, y1z2))
	FE(&res.Z).Multiply(vvv, z1z2)

	sameXCoord := FE(FE(new(F)).Multiply(&a.X, &b.Z)).Equal(FE(new(F)).Multiply(&b.X, &a.Z))
	sameYCoord := FE(FE(new(F)).Multiply(&a.Y, &b.Z)).Equal(FE(new(F)).Multiply(&b.Y, &a.Z))

	res.Select(new(Projective[C, P, F, FE]).Identity(), &res, (a.IsIdentity()&b.IsIdentity())|(sameXCoord&(1-sameYCoord)))
	res.Select(new(Projective[C, P, F, FE]).Double(a), &res, sameXCoord&sameYCoord)
	res.Select(b, &res, a.IsIdentity())
	return p.Select(a, &res, b.IsIdentity())
}

func (p *Projective[C, P, F, FE]) Double(v *Projective[C, P, F, FE]) *Projective[C, P, F, FE] {
	// dbl-1998-cmo-2
	var c C
	x1x1 := FE(new(F)).Square(&v.X)
	w := FE(new(F)).Multiply(c.A(), FE(new(F)).Square(&v.Z))
	FE(w).Add(w, x1x1)
	FE(w).Add(w, x1x1)
	FE(w).Add(w, x1x1)
	s := FE(new(F)).Multiply(&v.Y, &v.Z)
	ss := FE(new(F)).Square(s)
	sss := FE(new(F)).Multiply(ss, s)
	R := FE(new(F)).Multiply(&v.Y, s)
	B := FE(new(F)).Multiply(&v.X, R)
	B4 := FE(new(F)).Add(B, B)
	FE(B4).Add(B4, B4)
	h := FE(new(F)).Subtract(FE(new(F)).Square(w), FE(new(F)).Add(B4, B4))

	isIdentity := v.IsIdentity()

	FE(&p.X).Multiply(h, s)
	FE(&p.X).Add(&p.X, &p.X)

	RR6 := FE(new(F)).Square(R)
	FE(RR6).Add(RR6, RR6)
	FE(RR6).Add(RR6, RR6)
	FE(RR6).Add(RR6, RR6)

	FE(&p.Y).Multiply(w, FE(new(F)).Subtract(B4, h))
	FE(&p.Y).Subtract(&p.Y, RR6)

	FE(&p.Z).Add(sss, sss)
	FE(&p.Z).Add(sss, sss)
	FE(&p.Z).Add(sss, sss)

	return p.Select(new(Projective[C, P, F, FE]).Identity(), p, isIdentity)
}
func (p *Projective[C, P, F, FE]) BatchXY(points []Projective[C, P, F, FE], out []Xy[F]) *Projective[C, P, F, FE] {
	if len(points) != len(out) {
		panic("len(points) != len(out)")
	}
	FE(&p.X).Zero()
	FE(&p.Y).Zero()
	FE(&p.Z).Zero()

	z := make([]F, len(points))
	for i := range points {
		if points[i].IsIdentity() == 1 {
			panic("point is identity")
		}
		z = append(z, points[i].Z)
	}
	curve.BatchInvert[F, FE](&p.Z, utils.ValuesToPointers(z)...)

	for i := range points {
		FE(&out[i][0]).Multiply(&points[i].X, &z[i])
		FE(&out[i][1]).Multiply(&points[i].Y, &z[i])
	}
	return p
}
