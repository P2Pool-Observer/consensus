//go:build arm64 && !purego

#include "textflag.h"

#define aesenc(key, dst) \
	AESE V15.B16, dst \
	AESMC dst, dst \
	VEOR key, dst, dst

// func aes_rounds(state *[2]uint64, roundKeys *[aesRounds * 4]uint32) {
TEXT ·aes_rounds_internal(SB),NOSPLIT|NOFRAME,$0-16
    MOVD state+0(FP), R0
	MOVD roundKeys+8(FP), R1

	VLD1 (R0), [V0.B16]

	// zero
	VEOR V15.B16, V15.B16, V15.B16

	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)
	VLD1.P (R1), [V1.B16]
	aesenc(V1.B16, V0.B16)

    VST1 [V0.B16], (R0)

	RET

// func aes_single_round(dst, src *[2]uint64, roundKey *[2]uint64)
TEXT ·aes_single_round_internal(SB),NOSPLIT|NOFRAME,$0-24
    MOVD dst+0(FP), R0
	MOVD src+8(FP), R1
	MOVD roundKey+16(FP), R2

	VLD1 (R1), [V0.B16]
	VLD1 (R2), [V1.B16]

	// zero
	VEOR V15.B16, V15.B16, V15.B16

    aesenc(V1.B16, V0.B16)

    VST1 [V0.B16], (R0)

	RET
