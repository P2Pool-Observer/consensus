//go:build amd64 && !purego && goexperiment.simd

package cryptonight

import (
	"simd/archsimd"
	"unsafe"
)

func aes_rounds_internal(state *[16]uint64, roundKeys *[aesRounds * 4]uint32) {
	// #nosec G103
	state8 := (*[8][16]byte)(unsafe.Pointer(state))
	// #nosec G103
	rkey32 := (*[aesRounds][4]uint32)(unsafe.Pointer(roundKeys))

	X1 := archsimd.LoadUint32x4(&rkey32[0])
	X2 := archsimd.LoadUint32x4(&rkey32[1])
	X3 := archsimd.LoadUint32x4(&rkey32[2])
	X4 := archsimd.LoadUint32x4(&rkey32[3])
	X5 := archsimd.LoadUint32x4(&rkey32[4])
	X6 := archsimd.LoadUint32x4(&rkey32[5])
	X7 := archsimd.LoadUint32x4(&rkey32[6])
	X8 := archsimd.LoadUint32x4(&rkey32[7])
	X9 := archsimd.LoadUint32x4(&rkey32[8])
	X10 := archsimd.LoadUint32x4(&rkey32[9])

	var X0 archsimd.Uint8x16
	for i := range state8 {
		X0 = archsimd.LoadUint8x16(&state8[i])
		X0 = X0.AESEncryptOneRound(X1)
		X0 = X0.AESEncryptOneRound(X2)
		X0 = X0.AESEncryptOneRound(X3)
		X0 = X0.AESEncryptOneRound(X4)
		X0 = X0.AESEncryptOneRound(X5)
		X0 = X0.AESEncryptOneRound(X6)
		X0 = X0.AESEncryptOneRound(X7)
		X0 = X0.AESEncryptOneRound(X8)
		X0 = X0.AESEncryptOneRound(X9)
		X0 = X0.AESEncryptOneRound(X10)
		X0.Store(&state8[i])
	}
}

func load128bcast(x *[4]uint32) archsimd.Uint32x16 {
	var Y archsimd.Uint32x8
	var Z archsimd.Uint32x16
	X := archsimd.LoadUint32x4(x)
	Y = Y.SetLo(X).SetHi(X)
	Z = Z.SetLo(Y).SetHi(Y)
	return Z
}

func aes_rounds_internal_avx512(state *[16]uint64, roundKeys *[aesRounds * 4]uint32) {
	// #nosec G103
	state8 := (*[2][64]byte)(unsafe.Pointer(state))
	// #nosec G103
	rkey32 := (*[aesRounds][4]uint32)(unsafe.Pointer(roundKeys))

	Z1 := load128bcast(&rkey32[0])
	Z2 := load128bcast(&rkey32[1])
	Z3 := load128bcast(&rkey32[2])
	Z4 := load128bcast(&rkey32[3])
	Z5 := load128bcast(&rkey32[4])
	Z6 := load128bcast(&rkey32[5])
	Z7 := load128bcast(&rkey32[6])
	Z8 := load128bcast(&rkey32[7])
	Z9 := load128bcast(&rkey32[8])
	Z10 := load128bcast(&rkey32[9])

	var Z0 archsimd.Uint8x64
	for i := range state8 {
		Z0 = archsimd.LoadUint8x64(&state8[i])
		Z0 = Z0.AESEncryptOneRound(Z1)
		Z0 = Z0.AESEncryptOneRound(Z2)
		Z0 = Z0.AESEncryptOneRound(Z3)
		Z0 = Z0.AESEncryptOneRound(Z4)
		Z0 = Z0.AESEncryptOneRound(Z5)
		Z0 = Z0.AESEncryptOneRound(Z6)
		Z0 = Z0.AESEncryptOneRound(Z7)
		Z0 = Z0.AESEncryptOneRound(Z8)
		Z0 = Z0.AESEncryptOneRound(Z9)
		Z0 = Z0.AESEncryptOneRound(Z10)
		Z0.Store(&state8[i])
	}
}

func aes_single_round_internal(dst, src *[2]uint64, roundKey *[2]uint64) {
	// #nosec G103
	dst8 := (*[16]byte)(unsafe.Pointer(dst))
	// #nosec G103
	src8 := (*[16]byte)(unsafe.Pointer(src))
	// #nosec G103
	rkey32 := (*[4]uint32)(unsafe.Pointer(roundKey))

	X1 := archsimd.LoadUint32x4(rkey32)
	X0 := archsimd.LoadUint8x16(src8)
	X0 = X0.AESEncryptOneRound(X1)
	X0.Store(dst8)
}

func aes_rounds(state *[16]uint64, roundKeys *[aesRounds * 4]uint32) {
	if archsimd.X86.AVX() && archsimd.X86.AES() {
		if archsimd.X86.AVX512() && archsimd.X86.AVX512VAES() {
			aes_rounds_internal_avx512(state, roundKeys)
			return
		} else {
			aes_rounds_internal(state, roundKeys)
			return
		}
	}
	aes_rounds_generic(state, roundKeys)
}

func aes_single_round(dst, src *[2]uint64, roundKey *[2]uint64) {
	if archsimd.X86.AVX() && archsimd.X86.AES() {
		aes_single_round_internal(dst, src, roundKey)
		return
	}
	aes_single_round_generic(dst, src, roundKey)
}
