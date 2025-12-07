//go:build amd64 && !purego

package cryptonight

//go:nosplit
//go:noescape
func v2_sqrt(in uint64) (out uint64)
