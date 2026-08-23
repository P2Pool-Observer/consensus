package utils

import "crypto/subtle"

type Option[T any] struct {
	v  T
	ok bool
}

func (o Option[T]) Unwrap() T {
	if !o.ok {
		panic("unwrap None")
	}
	return o.v
}

func (o Option[T]) UnwrapOr(def T) T {
	if !o.ok {
		return def
	}
	return o.v
}

func (o Option[T]) Some() (T, bool) {
	return o.v, o.ok
}

func (o Option[T]) IsSome() bool {
	return o.ok
}

func (o Option[T]) Map(f func(T)) {
	if v, ok := o.Some(); ok {
		f(v)
	}
}

func (o *Option[T]) Mutable() (*T, bool) {
	if o.ok {
		return &o.v, true
	}
	return nil, false
}

func (o *Option[T]) MapMutable(f func(*T)) {
	if v, ok := o.Mutable(); ok {
		f(v)
	}
}

type ConstantTime[T any] interface {
	*T
	// Select sets v to a if cond == 1, and to b if cond == 0.
	Select(a, b *T, cond int) *T
	Equal(x *T) int
}

func MakeSome[T any](v T) Option[T] {
	return Option[T]{v: v, ok: true}
}

func MakeNone[T any]() Option[T] {
	return Option[T]{ok: false}
}

type ConstantOption[T any, CT ConstantTime[T]] struct {
	v  T
	ok int
}

func MakeConstantOption[T any, CT ConstantTime[T]](v T, ok int) *ConstantOption[T, CT] {
	return &ConstantOption[T, CT]{v: v, ok: ok}
}

func (o *ConstantOption[T, CT]) Unwrap() T {
	if o.ok == 0 {
		panic("unwrap None")
	}
	return o.v
}

func (o *ConstantOption[T, CT]) UnwrapOr(def *T) (v *T) {
	return CT(new(T)).Select(&o.v, def, o.ok)
}

func (o *ConstantOption[T, CT]) Some() (T, int) {
	return o.v, o.ok
}

func (o *ConstantOption[T, CT]) IsSome() int {
	return o.ok
}

func (o *ConstantOption[T, CT]) Select(a, b *ConstantOption[T, CT], cond int) *ConstantOption[T, CT] {
	return MakeConstantOption[T, CT](*CT(new(T)).Select(&a.v, &b.v, cond), subtle.ConstantTimeSelect(a.IsSome(), b.IsSome(), cond))
}

func (o *ConstantOption[T, CT]) Equal(x *ConstantOption[T, CT]) int {
	a := o.IsSome()
	b := x.IsSome()
	return (a & b & CT(&o.v).Equal(&x.v)) | ((1 - a) & (1 - b))
}

func (o *ConstantOption[T, CT]) Map(f func(T)) {
	f(*o.UnwrapOr(new(T)))
}

func (o *ConstantOption[T, CT]) MapMutable(f func(*T)) {
	v := o.UnwrapOr(new(T))
	f(v)
	CT(&o.v).Select(v, &o.v, o.IsSome())
}
