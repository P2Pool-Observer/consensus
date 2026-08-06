package generalized_bulletproofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
)

func ScalarPowers[F any, FE curve.BasicField[F]](x *F, size int) (res ScalarVector[F, FE]) {
	if size == 0 {
		panic("unsupported")
	}

	res = make([]F, 0, size)
	res = append(res, *FE(new(F)).One(), *x)
	for i := 2; i < size; i++ {
		res = append(res, *FE(new(F)).Multiply(&res[i-1], x))
	}
	// edge case of size == 1
	return res[:size:size]
}

type ScalarVector[F any, FE curve.BasicField[F]] []F

func (v ScalarVector[F, FE]) Split(at int) (a, b ScalarVector[F, FE]) {
	if len(v) <= 1 {
		panic("unreachable")
	}

	return v[:at], v[at:]
}

func (v ScalarVector[F, FE]) Sum() (out F) {
	FE(&out).Zero()
	for i := range v {
		FE(&out).Add(&out, &v[i])
	}
	return out
}

func (v ScalarVector[F, FE]) Copy(out ScalarVector[F, FE]) ScalarVector[F, FE] {
	out = append(out, v...)
	return out
}

// InnerProduct Returns sum(v * o)
func (v ScalarVector[F, FE]) InnerProduct(o ScalarVector[F, FE]) (out F) {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	return v.InnerProductUnchecked(o)
}

func (v ScalarVector[F, FE]) InnerProductUnchecked(o ScalarVector[F, FE]) (out F) {
	var tmp F
	FE(&out).Zero()
	for i := range min(len(v), len(o)) {
		//FE(&out).MultiplyAdd(&v[i], &o[i], &out)
		FE(&tmp).Multiply(&v[i], &o[i])
		FE(&out).Add(&tmp, &out)
	}
	return out
}

func (v ScalarVector[F, FE]) Add(s *F) ScalarVector[F, FE] {
	for i := range v {
		FE(&v[i]).Add(&v[i], s)
	}
	return v
}

func (v ScalarVector[F, FE]) Subtract(s *F) ScalarVector[F, FE] {
	for i := range v {
		FE(&v[i]).Subtract(&v[i], s)
	}
	return v
}

func (v ScalarVector[F, FE]) Multiply(s *F) ScalarVector[F, FE] {
	for i := range v {
		FE(&v[i]).Multiply(&v[i], s)
	}
	return v
}

func (v ScalarVector[F, FE]) AddVec(o ScalarVector[F, FE]) ScalarVector[F, FE] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	return v.AddVecUnchecked(o)
}

func (v ScalarVector[F, FE]) AddVecUnchecked(o ScalarVector[F, FE]) ScalarVector[F, FE] {
	for i := range min(len(v), len(o)) {
		FE(&v[i]).Add(&v[i], &o[i])
	}
	return v
}

func (v ScalarVector[F, FE]) SubtractVec(o ScalarVector[F, FE]) ScalarVector[F, FE] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		FE(&v[i]).Subtract(&v[i], &o[i])
	}
	return v
}

func (v ScalarVector[F, FE]) MultiplyVec(o ScalarVector[F, FE]) ScalarVector[F, FE] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		FE(&v[i]).Multiply(&v[i], &o[i])
	}
	return v
}

type PointVector[P any, F any, PE curve.ExtraCurvePoint[P, F], FE curve.BasicField[F]] []P

func (v PointVector[P, F, PE, FE]) Split() (a, b PointVector[P, F, PE, FE]) {
	if len(v) <= 1 || len(v)%2 != 0 {
		panic("unreachable")
	}

	return v[:len(v)/2], v[len(v)/2:]
}

func (v PointVector[P, F, PE, FE]) Copy(out PointVector[P, F, PE, FE]) PointVector[P, F, PE, FE] {
	out = append(out, v...)
	return out
}

func (v PointVector[P, F, PE, FE]) Multiply(scalar *F) PointVector[P, F, PE, FE] {
	for i := range v {
		PE(&v[i]).ScalarMult(scalar, &v[i])
	}
	return v
}

func (v PointVector[P, F, PE, FE]) AddVec(o PointVector[P, F, PE, FE]) PointVector[P, F, PE, FE] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		PE(&v[i]).Add(&v[i], &o[i])
	}
	return v
}

func (v PointVector[P, F, PE, FE]) SubtractVec(o PointVector[P, F, PE, FE]) PointVector[P, F, PE, FE] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		PE(&v[i]).Subtract(&v[i], &o[i])
	}
	return v
}

func (v PointVector[P, F, PE, FE]) MultiplyVec(o ScalarVector[F, FE]) PointVector[P, F, PE, FE] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		PE(&v[i]).ScalarMult(&o[i], &v[i])
	}
	return v
}

func (v PointVector[P, F, PE, FE]) MultiExp(dst *P, scalars ScalarVector[F, FE]) *P {
	if len(scalars) != len(v) {
		panic("len mismatch")
	}
	pairs := make([]multiexp.ScalarPointPair[P, F, PE, FE], 0, len(v))
	for i := range v {
		pairs = append(pairs, multiexp.ScalarPointPair[P, F, PE, FE]{S: scalars[i], P: v[i]})
	}
	return multiexp.MultiExp(dst, pairs)
}
