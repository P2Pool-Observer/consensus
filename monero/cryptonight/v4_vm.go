package cryptonight

import (
	"math/bits"
)

type op struct {
	opcode uint8
	src    *uint32
	imm    uint32
}

const (
	mul_0_0 = uint8(iota)
	mul_1_0
	mul_2_0
	mul_3_0
	mul_0_1
	mul_1_1
	mul_2_1
	mul_3_1
	mul_0_2
	mul_1_2
	mul_2_2
	mul_3_2
	mul_0_3
	mul_1_3
	mul_2_3
	mul_3_3
	mul_0_imm
	mul_1_imm
	mul_2_imm
	mul_3_imm

	add_0_0
	add_1_0
	add_2_0
	add_3_0
	add_0_1
	add_1_1
	add_2_1
	add_3_1
	add_0_2
	add_1_2
	add_2_2
	add_3_2
	add_0_3
	add_1_3
	add_2_3
	add_3_3
	add_0_imm
	add_1_imm
	add_2_imm
	add_3_imm

	sub_0_0
	sub_1_0
	sub_2_0
	sub_3_0
	sub_0_1
	sub_1_1
	sub_2_1
	sub_3_1
	sub_0_2
	sub_1_2
	sub_2_2
	sub_3_2
	sub_0_3
	sub_1_3
	sub_2_3
	sub_3_3
	sub_0_imm
	sub_1_imm
	sub_2_imm
	sub_3_imm

	ror_0_0
	ror_1_0
	ror_2_0
	ror_3_0
	ror_0_1
	ror_1_1
	ror_2_1
	ror_3_1
	ror_0_2
	ror_1_2
	ror_2_2
	ror_3_2
	ror_0_3
	ror_1_3
	ror_2_3
	ror_3_3
	ror_0_imm
	ror_1_imm
	ror_2_imm
	ror_3_imm

	rol_0_0
	rol_1_0
	rol_2_0
	rol_3_0
	rol_0_1
	rol_1_1
	rol_2_1
	rol_3_1
	rol_0_2
	rol_1_2
	rol_2_2
	rol_3_2
	rol_0_3
	rol_1_3
	rol_2_3
	rol_3_3
	rol_0_imm
	rol_1_imm
	rol_2_imm
	rol_3_imm

	xor_0_0
	xor_1_0
	xor_2_0
	xor_3_0
	xor_0_1
	xor_1_1
	xor_2_1
	xor_3_1
	xor_0_2
	xor_1_2
	xor_2_2
	xor_3_2
	xor_0_3
	xor_1_3
	xor_2_3
	xor_3_3
	xor_0_imm
	xor_1_imm
	xor_2_imm
	xor_3_imm

	ret
)

func r_op_emit(opcode V4Opcode, srcIndex, dstIndex uint8, r [5]*uint32) (iop op) {
	if srcIndex < 4 {
		iop.opcode = uint8(uint32(opcode)*4*5 + uint32(srcIndex)*4 + uint32(dstIndex))
	} else {
		iop.opcode = uint8(uint32(opcode)*4*5 + 4*4 + uint32(dstIndex))
		iop.src = r[srcIndex-4]
	}
	return iop
}

//go:nosplit
func r_op_interpreter(code *[V4_NUM_INSTRUCTIONS_MAX + 1]op, r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	const REG_BITS = 4 * 8

	var j uint8
	var src *uint32
	var imm uint32
	for i := range code {
		j = code[i].opcode
		src = code[i].src
		imm = code[i].imm

		switch j {
		case mul_0_0:
			r0 *= r0
		case mul_1_0:
			r1 *= r0
		case mul_2_0:
			r2 *= r0
		case mul_3_0:
			r3 *= r0
		case mul_0_1:
			r0 *= r1
		case mul_1_1:
			r1 *= r1
		case mul_2_1:
			r2 *= r1
		case mul_3_1:
			r3 *= r1
		case mul_0_2:
			r0 *= r2
		case mul_1_2:
			r1 *= r2
		case mul_2_2:
			r2 *= r2
		case mul_3_2:
			r3 *= r2
		case mul_0_3:
			r0 *= r3
		case mul_1_3:
			r1 *= r3
		case mul_2_3:
			r2 *= r3
		case mul_3_3:
			r3 *= r3
		case mul_0_imm:
			r0 *= *src
		case mul_1_imm:
			r1 *= *src
		case mul_2_imm:
			r2 *= *src
		case mul_3_imm:
			r3 *= *src

		case add_0_0:
			r0 += r0 + imm
		case add_1_0:
			r1 += r0 + imm
		case add_2_0:
			r2 += r0 + imm
		case add_3_0:
			r3 += r0 + imm
		case add_0_1:
			r0 += r1 + imm
		case add_1_1:
			r1 += r1 + imm
		case add_2_1:
			r2 += r1 + imm
		case add_3_1:
			r3 += r1 + imm
		case add_0_2:
			r0 += r2 + imm
		case add_1_2:
			r1 += r2 + imm
		case add_2_2:
			r2 += r2 + imm
		case add_3_2:
			r3 += r2 + imm
		case add_0_3:
			r0 += r3 + imm
		case add_1_3:
			r1 += r3 + imm
		case add_2_3:
			r2 += r3 + imm
		case add_3_3:
			r3 += r3 + imm
		case add_0_imm:
			r0 += *src + imm
		case add_1_imm:
			r1 += *src + imm
		case add_2_imm:
			r2 += *src + imm
		case add_3_imm:
			r3 += *src + imm

		case sub_1_0:
			r1 -= r0
		case sub_2_0:
			r2 -= r0
		case sub_3_0:
			r3 -= r0
		case sub_0_1:
			r0 -= r1
		case sub_2_1:
			r2 -= r1
		case sub_3_1:
			r3 -= r1
		case sub_0_2:
			r0 -= r2
		case sub_1_2:
			r1 -= r2
		case sub_3_2:
			r3 -= r2
		case sub_0_3:
			r0 -= r3
		case sub_1_3:
			r1 -= r3
		case sub_2_3:
			r2 -= r3
		case sub_0_imm:
			r0 -= *src
		case sub_1_imm:
			r1 -= *src
		case sub_2_imm:
			r2 -= *src
		case sub_3_imm:
			r3 -= *src

		case ror_0_0:
			r0 = bits.RotateLeft32(r0, REG_BITS-int(r0%REG_BITS))
		case ror_1_0:
			r1 = bits.RotateLeft32(r1, REG_BITS-int(r0%REG_BITS))
		case ror_2_0:
			r2 = bits.RotateLeft32(r2, REG_BITS-int(r0%REG_BITS))
		case ror_3_0:
			r3 = bits.RotateLeft32(r3, REG_BITS-int(r0%REG_BITS))
		case ror_0_1:
			r0 = bits.RotateLeft32(r0, REG_BITS-int(r1%REG_BITS))
		case ror_1_1:
			r1 = bits.RotateLeft32(r1, REG_BITS-int(r1%REG_BITS))
		case ror_2_1:
			r2 = bits.RotateLeft32(r2, REG_BITS-int(r1%REG_BITS))
		case ror_3_1:
			r3 = bits.RotateLeft32(r3, REG_BITS-int(r1%REG_BITS))
		case ror_0_2:
			r0 = bits.RotateLeft32(r0, REG_BITS-int(r2%REG_BITS))
		case ror_1_2:
			r1 = bits.RotateLeft32(r1, REG_BITS-int(r2%REG_BITS))
		case ror_2_2:
			r2 = bits.RotateLeft32(r2, REG_BITS-int(r2%REG_BITS))
		case ror_3_2:
			r3 = bits.RotateLeft32(r3, REG_BITS-int(r2%REG_BITS))
		case ror_0_3:
			r0 = bits.RotateLeft32(r0, REG_BITS-int(r3%REG_BITS))
		case ror_1_3:
			r1 = bits.RotateLeft32(r1, REG_BITS-int(r3%REG_BITS))
		case ror_2_3:
			r2 = bits.RotateLeft32(r2, REG_BITS-int(r3%REG_BITS))
		case ror_3_3:
			r3 = bits.RotateLeft32(r3, REG_BITS-int(r3%REG_BITS))
		case ror_0_imm:
			r0 = bits.RotateLeft32(r0, REG_BITS-int(*src%REG_BITS))
		case ror_1_imm:
			r1 = bits.RotateLeft32(r1, REG_BITS-int(*src%REG_BITS))
		case ror_2_imm:
			r2 = bits.RotateLeft32(r2, REG_BITS-int(*src%REG_BITS))
		case ror_3_imm:
			r3 = bits.RotateLeft32(r3, REG_BITS-int(*src%REG_BITS))

		case rol_0_0:
			r0 = bits.RotateLeft32(r0, int(r0%REG_BITS))
		case rol_1_0:
			r1 = bits.RotateLeft32(r1, int(r0%REG_BITS))
		case rol_2_0:
			r2 = bits.RotateLeft32(r2, int(r0%REG_BITS))
		case rol_3_0:
			r3 = bits.RotateLeft32(r3, int(r0%REG_BITS))
		case rol_0_1:
			r0 = bits.RotateLeft32(r0, int(r1%REG_BITS))
		case rol_1_1:
			r1 = bits.RotateLeft32(r1, int(r1%REG_BITS))
		case rol_2_1:
			r2 = bits.RotateLeft32(r2, int(r1%REG_BITS))
		case rol_3_1:
			r3 = bits.RotateLeft32(r3, int(r1%REG_BITS))
		case rol_0_2:
			r0 = bits.RotateLeft32(r0, int(r2%REG_BITS))
		case rol_1_2:
			r1 = bits.RotateLeft32(r1, int(r2%REG_BITS))
		case rol_2_2:
			r2 = bits.RotateLeft32(r2, int(r2%REG_BITS))
		case rol_3_2:
			r3 = bits.RotateLeft32(r3, int(r2%REG_BITS))
		case rol_0_3:
			r0 = bits.RotateLeft32(r0, int(r3%REG_BITS))
		case rol_1_3:
			r1 = bits.RotateLeft32(r1, int(r3%REG_BITS))
		case rol_2_3:
			r2 = bits.RotateLeft32(r2, int(r3%REG_BITS))
		case rol_3_3:
			r3 = bits.RotateLeft32(r3, int(r3%REG_BITS))
		case rol_0_imm:
			r0 = bits.RotateLeft32(r0, int(*src%REG_BITS))
		case rol_1_imm:
			r1 = bits.RotateLeft32(r1, int(*src%REG_BITS))
		case rol_2_imm:
			r2 = bits.RotateLeft32(r2, int(*src%REG_BITS))
		case rol_3_imm:
			r3 = bits.RotateLeft32(r3, int(*src%REG_BITS))

		case xor_1_0:
			r1 ^= r0
		case xor_2_0:
			r2 ^= r0
		case xor_3_0:
			r3 ^= r0
		case xor_0_1:
			r0 ^= r1
		case xor_2_1:
			r2 ^= r1
		case xor_3_1:
			r3 ^= r1
		case xor_0_2:
			r0 ^= r2
		case xor_1_2:
			r1 ^= r2
		case xor_3_2:
			r3 ^= r2
		case xor_0_3:
			r0 ^= r3
		case xor_1_3:
			r1 ^= r3
		case xor_2_3:
			r2 ^= r3
		case xor_0_imm:
			r0 ^= *src
		case xor_1_imm:
			r1 ^= *src
		case xor_2_imm:
			r2 ^= *src
		case xor_3_imm:
			r3 ^= *src

		case ret:
			return r0, r1, r2, r3
		}
	}
	return r0, r1, r2, r3
}
