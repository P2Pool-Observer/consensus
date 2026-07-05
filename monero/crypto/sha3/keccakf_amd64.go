//go:build amd64 && !purego

package sha3

import "golang.org/x/sys/cpu"

//go:noescape
func KeccakF1600(a *[200]byte)

const KeccakX2Supported = false

var KeccakX4Supported = cpu.X86.HasAVX && cpu.X86.HasAVX2

//go:noescape
func KeccakF1600x4(a *[100]uint64)
