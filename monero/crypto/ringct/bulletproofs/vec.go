package bulletproofs

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

var two = (&curve25519.PrivateKeyBytes{2}).Scalar()

var twoScalarVectorPowers = AppendScalarVectorPowers[curve25519.ConstantTimeOperations](nil, two, CommitmentBits)

func TwoScalarVectorPowers[T curve25519.PointOperations]() ScalarVector[T] {
	return ScalarVector[T](twoScalarVectorPowers)
}

func AppendScalarVectorPowers[T curve25519.PointOperations](out ScalarVector[T], x *curve25519.Scalar, size int) ScalarVector[T] {
	if size == 0 {
		return out
	}
	n := len(out)
	out = append(out, *(&curve25519.PrivateKeyBytes{1}).Scalar(), *x)
	var tmp curve25519.Scalar
	for i := 2; i < size; i++ {
		out = append(out, *tmp.Multiply(&out[i-1+n], x))
	}
	return out[:size+n]
}

type ScalarVector[T curve25519.PointOperations] []curve25519.Scalar

func (v ScalarVector[T]) Split() (a, b ScalarVector[T]) {
	if len(v) <= 1 || len(v)%2 != 0 {
		panic("unreachable")
	}

	return v[:len(v)/2], v[len(v)/2:]
}

func (v ScalarVector[T]) Sum() (out curve25519.Scalar) {
	for i := range v {
		out.Add(&out, &v[i])
	}
	return out
}

func (v ScalarVector[T]) Copy(out ScalarVector[T]) ScalarVector[T] {
	out = append(out, v...)
	return out
}

// InnerProduct Returns sum(v * o)
func (v ScalarVector[T]) InnerProduct(o ScalarVector[T]) (out curve25519.Scalar) {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		out.MultiplyAdd(&v[i], &o[i], &out)
	}
	return out
}

// WeightedInnerProduct Returns sum(v * x * y * o)
func (v ScalarVector[T]) WeightedInnerProduct(x, y ScalarVector[T]) (out curve25519.Scalar) {
	if len(x) != len(v) || len(y) != len(v) {
		panic("len mismatch")
	}
	var tmp curve25519.Scalar
	for i := range v {
		tmp.Multiply(&v[i], &x[i])
		out.MultiplyAdd(&tmp, &y[i], &out)
	}
	return out
}

// WeightedWeightedInnerProduct Returns sum(v * [x] * y * z * o)
func (v ScalarVector[T]) WeightedWeightedInnerProduct(x *curve25519.Scalar, y, z ScalarVector[T]) (out curve25519.Scalar) {
	if len(y) != len(v) || len(z) != len(v) {
		panic("len mismatch")
	}
	var tmp curve25519.Scalar
	for i := range v {
		tmp.Multiply(&v[i], x)
		tmp.Multiply(&tmp, &y[i])
		out.MultiplyAdd(&tmp, &z[i], &out)
	}
	return out
}

func (v ScalarVector[T]) Add(s *curve25519.Scalar) ScalarVector[T] {
	for i := range v {
		v[i].Add(&v[i], s)
	}
	return v
}

func (v ScalarVector[T]) Subtract(s *curve25519.Scalar) ScalarVector[T] {
	for i := range v {
		v[i].Subtract(&v[i], s)
	}
	return v
}

func (v ScalarVector[T]) Multiply(s *curve25519.Scalar) ScalarVector[T] {
	for i := range v {
		v[i].Multiply(&v[i], s)
	}
	return v
}

func (v ScalarVector[T]) AddVec(o ScalarVector[T]) ScalarVector[T] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		v[i].Add(&v[i], &o[i])
	}
	return v
}

func (v ScalarVector[T]) AddVecMultiply(o ScalarVector[T], s *curve25519.Scalar) ScalarVector[T] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		v[i].MultiplyAdd(&o[i], s, &v[i])
	}
	return v
}

func (v ScalarVector[T]) SubtractVec(o ScalarVector[T]) ScalarVector[T] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		v[i].Subtract(&v[i], &o[i])
	}
	return v
}

func (v ScalarVector[T]) MultiplyVec(o ScalarVector[T]) ScalarVector[T] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		v[i].Multiply(&v[i], &o[i])
	}
	return v
}

func (v ScalarVector[T]) MultiplyPublicKeys(dst *curve25519.PublicKey[T], points []*curve25519.PublicKey[T]) *curve25519.PublicKey[T] {
	if len(points) != len(v) {
		panic("len mismatch")
	}
	scalars := make([]*curve25519.Scalar, len(v))
	for i := range v {
		scalars[i] = &v[i]
	}
	return dst.MultiScalarMult(scalars, points)
}

func (v ScalarVector[T]) MultiplyPoints(dst *curve25519.PublicKey[T], points []*curve25519.Point) *curve25519.PublicKey[T] {
	if len(points) != len(v) {
		panic("len mismatch")
	}
	scalars := make([]*curve25519.Scalar, len(v))
	for i := range v {
		scalars[i] = &v[i]
	}
	return dst.MultiScalarMultPoints(scalars, points)
}

type PointVector[T curve25519.PointOperations] []curve25519.PublicKey[T]

func (v PointVector[T]) Split() (a, b PointVector[T]) {
	if len(v) <= 1 || len(v)%2 != 0 {
		panic("unreachable")
	}

	return v[:len(v)/2], v[len(v)/2:]
}

func (v PointVector[T]) Copy(out PointVector[T]) PointVector[T] {
	out = append(out, v...)
	return out
}

func (v PointVector[T]) MultiplyVec(o ScalarVector[T]) PointVector[T] {
	if len(o) != len(v) {
		panic("len mismatch")
	}
	for i := range v {
		v[i].ScalarMult(&o[i], &v[i])
	}
	return v
}

func (v PointVector[T]) MultiplyScalars(dst *curve25519.PublicKey[T], scalars ScalarVector[T]) *curve25519.PublicKey[T] {
	if len(scalars) != len(v) {
		panic("len mismatch")
	}
	points := make([]*curve25519.PublicKey[T], len(v))
	for i := range v {
		points[i] = &v[i]
	}
	return scalars.MultiplyPublicKeys(dst, points)
}
