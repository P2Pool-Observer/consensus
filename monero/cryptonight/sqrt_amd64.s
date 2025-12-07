//go:build amd64 && !purego

#include "textflag.h"


// func v2_sqrt(in uint64) (out uint64)
TEXT ·v2_sqrt(SB),NOSPLIT|NOFRAME,$0-16
	MOVQ    in+0(FP), R14

	// <BEGIN> VARIANT2_INTEGER_MATH_SQRT_STEP
	MOVQ    R14, AX
	SHRQ    $12, AX
	MOVQ    $(1023 << 52), BX
	ADDQ    BX, AX
	MOVQ    AX, X0
	SQRTSD  X0, X0
	MOVQ    X0, R13
	SUBQ    BX, R13
	SHRQ    $19, R13        // not yet sanitized sqrt result
	// <END> VARIANT2_INTEGER_MATH_SQRT_STEP
	// <BEGIN> VARIANT2_INTEGER_MATH_SQRT_FIXUP
	MOVQ    R13, AX
	SHRQ    $1, AX            // s = sqrtResult >> 1
	MOVQ    R13, BX
	ANDQ    $1, BX            // b = sqrtResult & 1
	MOVQ    R13, CX
	SHLQ    $32, CX
	LEAQ    0(AX)(BX*1), DX
	IMULQ   AX, DX
	ADDQ    DX, CX            // r2 = s * (s + b) + (sqrtResult << 32)

	ADDQ    CX, BX
	XORQ    DX, DX
	CMPQ    BX, R14
	SETHI   DL
	SUBQ    DX, R13         // sqrtResult += ((r2 + b > sqrtInput) ? -1 : 0)


	MOVQ    $0x100000000, DX
	LEAQ    0(CX)(DX*1), BX
	SUBQ    AX, R14
	XORQ    DX, DX
	CMPQ    BX, R14
	SETCS   DL
	ADDQ    DX, R13      // sqrtResult += ((r2 + (1 << 32) < sqrtInput - s) ? 1 : 0)

	// <END> VARIANT2_INTEGER_MATH_SQRT_FIXUP

	MOVQ    R13, out+8(FP)
	RET
