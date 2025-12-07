package cryptonight

type Variant uint8

const (
	V0 = Variant(iota)
	V1
	V2
	V3
	V4
	R = V4
)
