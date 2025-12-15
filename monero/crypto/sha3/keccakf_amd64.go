//go:build amd64 && !purego

package sha3

//go:noescape
func KeccakF1600(a *[200]byte)
