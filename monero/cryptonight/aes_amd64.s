//go:build amd64 && !purego

#include "textflag.h"

// func aes_rounds(state *[2]uint64, roundKeys *[aesRounds * 4]uint32) {
TEXT ·aes_rounds_internal(SB),NOSPLIT|NOFRAME,$0-16
    MOVQ state+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVAPD 0(AX), X0

	MOVAPD 0*16(BX), X1
	AESENC X1, X0
	MOVAPD 1*16(BX), X1
	AESENC X1, X0
	MOVAPD 2*16(BX), X1
	AESENC X1, X0
	MOVAPD 3*16(BX), X1
	AESENC X1, X0
	MOVAPD 4*16(BX), X1
	AESENC X1, X0
	MOVAPD 5*16(BX), X1
	AESENC X1, X0
	MOVAPD 6*16(BX), X1
	AESENC X1, X0
	MOVAPD 7*16(BX), X1
	AESENC X1, X0
	MOVAPD 8*16(BX), X1
	AESENC X1, X0
	MOVAPD 9*16(BX), X1
	AESENC X1, X0

	MOVUPD X0, 0(AX)
	RET

// func aes_single_round(dst, src *[2]uint64, roundKey *[2]uint64)
TEXT ·aes_single_round_internal(SB),NOSPLIT|NOFRAME,$0-24
    MOVQ dst+0(FP), AX
	MOVQ src+8(FP), BX
	MOVQ roundKey+16(FP), CX

	MOVAPD 0(BX), X0
	MOVUPD 0(CX), X1

	AESENC X1, X0

	MOVUPD X0, 0(AX)
	RET
