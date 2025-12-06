package utils

func ValuesToPointers[T any, S ~[]T](x S) []*T {
	out := make([]*T, len(x))
	for i := range x {
		out[i] = &x[i]
	}
	return out
}
