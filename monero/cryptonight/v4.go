package cryptonight

import (
	"encoding/binary"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight/internal/blake256"
)

const (
	// V4_TOTAL_LATENCY Generate code with minimal theoretical latency = 45 cycles, which is equivalent to 15 multiplications
	V4_TOTAL_LATENCY = 15 * 3

	// V4_NUM_INSTRUCTIONS_MIN Always generate at least 60 instructions
	V4_NUM_INSTRUCTIONS_MIN = 60

	// V4_NUM_INSTRUCTIONS_MAX Never generate more than 70 instructions (final RET instruction doesn't count here)
	V4_NUM_INSTRUCTIONS_MAX = 70

	// V4_ALU_COUNT_MUL Available ALUs for MUL
	// Modern CPUs typically have only 1 ALU which can do multiplications
	V4_ALU_COUNT_MUL = 1

	// V4_ALU_COUNT Total available ALUs
	// Modern CPUs have 4 ALUs, but we use only 3 because random math executes together with other main loop code
	V4_ALU_COUNT = 3
)

type V4Opcode uint8

const (
	// V4_MUL a*b
	V4_MUL = V4Opcode(iota)
	// V4_ADD a+b + C, C is an unsigned 32-bit constant
	V4_ADD
	// V4_SUB a-b
	V4_SUB
	// V4_ROR rotate right "a" by "b & 31" bits
	V4_ROR
	// V4_ROL rotate left "a" by "b & 31" bits
	V4_ROL
	// V4_XOR a^b
	V4_XOR
	// V4_RET finish execution
	V4_RET

	V4_OPS = V4_RET
)

const (
	V4_OPCODE_BITS    = 3
	V4_DST_INDEX_BITS = 2
	V4_SRC_INDEX_BITS = 3
)

// MUL is 3 cycles, 3-way addition and rotations are 2 cycles, SUB/XOR are 1 cycle
// These latencies match real-life instruction latencies for Intel CPUs starting from Sandy Bridge and up to Skylake/Coffee lake
//
// AMD Ryzen has the same latencies except 1-cycle ROR/ROL, so it'll be a bit faster than Intel Sandy Bridge and newer processors
// Surprisingly, Intel Nehalem also has 1-cycle ROR/ROL, so it'll also be faster than Intel Sandy Bridge and newer processors
// AMD Bulldozer has 4 cycles latency for MUL (slower than Intel) and 1 cycle for ROR/ROL (faster than Intel), so average performance will be the same
// Source: https://www.agner.org/optimize/instruction_tables.pdf

var opLatency = [V4_OPS]int{3, 2, 1, 2, 2, 1}

// Instruction latencies for theoretical ASIC implementation
var asicOpLatency = [V4_OPS]int{3, 1, 1, 1, 1, 1}

// Available ALUs for each instruction
var opALUs = [V4_OPS]int{V4_ALU_COUNT_MUL, V4_ALU_COUNT, V4_ALU_COUNT, V4_ALU_COUNT, V4_ALU_COUNT, V4_ALU_COUNT}

var pattern = [3]V4Opcode{V4_ROR, V4_MUL, V4_MUL}

func r_init(code *[V4_NUM_INSTRUCTIONS_MAX + 1]op, height uint64, r [5]*uint32) uint32 {

	var data [32]int8
	// #nosec G103
	dataU8 := (*[32]byte)(unsafe.Pointer(&data))
	binary.LittleEndian.PutUint64(dataU8[:], height)
	data[20] = -38

	// Set data_index past the last byte in data
	// to trigger full data update with blake hash
	// before we start using it
	dataIndex := len(data)

	var codeSize uint32

	// There is a small chance (1.8%) that register R8 won't be used in the generated program
	// So we keep track of it and try again if it's not used
	var r8Used bool
	for {
		var latency [9]int
		var asicLatency [9]int

		// Tracks previous instruction and value of the source operand for registers R0-R3 throughout code execution
		// byte 0: current value of the destination register
		// byte 1: instruction opcode
		// byte 2: current value of the source register
		//
		// Registers R4-R8 are constant and are treated as having the same value because when we do
		// the same operation twice with two constant source registers, it can be optimized into a single operation
		var instData = [9]uint32{0, 1, 2, 3, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF}

		var aluBusy [V4_TOTAL_LATENCY + 1][V4_ALU_COUNT]bool
		var isRotation [V4_OPS]bool
		var rotated [4]bool
		var rotateCount int
		isRotation[V4_ROR] = true
		isRotation[V4_ROL] = true

		var numRetries int
		codeSize = 0

		var totalIterations int
		r8Used = false

		// Generate random code to achieve minimal required latency for our abstract CPU
		// Try to get this latency for all 4 registers
		for (latency[0] < V4_TOTAL_LATENCY || latency[1] < V4_TOTAL_LATENCY || latency[2] < V4_TOTAL_LATENCY || latency[3] < V4_TOTAL_LATENCY) && numRetries < 64 {

			// Fail-safe to guarantee loop termination
			totalIterations++
			if totalIterations > 256 {
				break
			}

			dataIndex = r_check_data(dataIndex, 1, dataU8)

			c := uint8(data[dataIndex])
			dataIndex++

			// MUL = opcodes 0-2
			// ADD = opcode 3
			// SUB = opcode 4
			// ROR/ROL = opcode 5, shift direction is selected randomly
			// XOR = opcodes 6-7
			opcode := V4Opcode(c & ((1 << V4_OPCODE_BITS) - 1))
			if opcode == 5 {
				dataIndex = r_check_data(dataIndex, 1, dataU8)
				if data[dataIndex] >= 0 {
					opcode = V4_ROR
				} else {
					opcode = V4_ROL
				}
				dataIndex++
			} else if opcode >= 6 {
				opcode = V4_XOR
			} else if opcode <= 2 {
				opcode = V4_MUL
			} else {
				opcode -= 2
			}

			dstIndex := (c >> V4_OPCODE_BITS) & ((1 << V4_DST_INDEX_BITS) - 1)
			srcIndex := (c >> (V4_OPCODE_BITS + V4_DST_INDEX_BITS)) & ((1 << V4_SRC_INDEX_BITS) - 1)

			a := dstIndex
			b := srcIndex

			// Don't do ADD/SUB/XOR with the same register
			if ((opcode == V4_ADD) || (opcode == V4_SUB) || (opcode == V4_XOR)) && a == b {
				// Use register R8 as source instead
				b = 8
				srcIndex = 8
			}

			// Don't do rotation with the same destination twice because it's equal to a single rotation
			if isRotation[opcode] && rotated[a] {
				continue
			}

			// Don't do the same instruction (except MUL) with the same source value twice because all other cases can be optimized:
			// 2xADD(a, b, C) = ADD(a, b*2, C1+C2), same for SUB and rotations
			// 2xXOR(a, b) = NOP
			if (opcode != V4_MUL) && ((instData[a] & 0xFFFF00) == (uint32(opcode)<<8)+((instData[b]&255)<<16)) {
				continue
			}

			// Find which ALU is available (and when) for this instruction
			nextLatency := max(latency[a], latency[b])
			aluIndex := -1
			for nextLatency < V4_TOTAL_LATENCY {
				for i := opALUs[opcode] - 1; i >= 0; i-- {
					if !aluBusy[nextLatency][i] {
						// ADD is implemented as two 1-cycle instructions on a real CPU, so do an additional availability check
						if opcode == V4_ADD && aluBusy[nextLatency+1][i] {
							continue
						}

						// Rotation can only start when previous rotation is finished, so do an additional availability check
						if isRotation[opcode] && (nextLatency < rotateCount*opLatency[opcode]) {
							continue
						}

						aluIndex = i
						break
					}
				}

				if aluIndex >= 0 {
					break
				}
				nextLatency++
			}

			// Don't generate instructions that leave some register unchanged for more than 7 cycles
			if nextLatency > latency[a]+7 {
				continue
			}

			nextLatency += opLatency[opcode]

			if nextLatency <= V4_TOTAL_LATENCY {
				if isRotation[opcode] {
					rotateCount++
				}

				// Mark ALU as busy only for the first cycle when it starts executing the instruction because ALUs are fully pipelined
				aluBusy[nextLatency-opLatency[opcode]][aluIndex] = true
				latency[a] = nextLatency

				// ASIC is supposed to have enough ALUs to run as many independent instructions per cycle as possible, so latency calculation for ASIC is simple
				asicLatency[a] = max(asicLatency[a], asicLatency[b]) + asicOpLatency[opcode]

				rotated[a] = isRotation[opcode]

				instData[a] = codeSize + (uint32(opcode) << 8) + ((instData[b] & 255) << 16)

				code[codeSize] = r_op_emit(opcode, srcIndex, dstIndex, r)

				if srcIndex == 8 {
					r8Used = true
				}

				if opcode == V4_ADD {
					// ADD instruction is implemented as two 1-cycle instructions on a real CPU, so mark ALU as busy for the next cycle too
					aluBusy[nextLatency-opLatency[opcode]+1][aluIndex] = true

					// ADD instruction requires 4 more random bytes for 32-bit constant "C" in "a = a + b + C"
					dataIndex = r_check_data(dataIndex, 4, dataU8)
					code[codeSize].imm = binary.LittleEndian.Uint32(dataU8[dataIndex:])
					dataIndex += 4
				}

				codeSize++
				if codeSize >= V4_NUM_INSTRUCTIONS_MIN {
					break
				}
			} else {
				numRetries++
			}
		}
		// ASIC has more execution resources and can extract as much parallelism from the code as possible
		// We need to add a few more MUL and ROR instructions to achieve minimal required latency for ASIC
		// Get this latency for at least 1 of the 4 registers

		prevCodeSize := codeSize

		for codeSize < V4_NUM_INSTRUCTIONS_MAX && asicLatency[0] < V4_TOTAL_LATENCY && asicLatency[1] < V4_TOTAL_LATENCY && asicLatency[2] < V4_TOTAL_LATENCY && asicLatency[3] < V4_TOTAL_LATENCY {

			minIdx := 0
			maxIdx := 0
			for i := 1; i < 4; i++ {
				if asicLatency[i] < asicLatency[minIdx] {
					minIdx = i
				}
				if asicLatency[i] > asicLatency[maxIdx] {
					maxIdx = i
				}
			}

			opcode := pattern[(codeSize-prevCodeSize)%3]
			latency[minIdx] = latency[maxIdx] + opLatency[opcode]
			asicLatency[minIdx] = asicLatency[maxIdx] + asicOpLatency[opcode]

			code[codeSize] = r_op_emit(opcode, uint8(maxIdx), uint8(minIdx), r)
			codeSize++
		}

		// There is ~98.15% chance that loop condition is false, so this loop will execute only 1 iteration most of the time
		// It never does more than 4 iterations for all block heights < 10,000,000
		if !r8Used || codeSize < V4_NUM_INSTRUCTIONS_MIN || codeSize > V4_NUM_INSTRUCTIONS_MAX {
			continue
		}
		break
	}

	// It's guaranteed that NUM_INSTRUCTIONS_MIN <= code_size <= NUM_INSTRUCTIONS_MAX here
	// Add final instruction to stop the interpreter
	code[codeSize] = r_op_emit(V4_RET, 0, 0, r)

	return codeSize
}

func r_check_data(dataIndex, needed int, data *[32]uint8) int {
	if dataIndex+needed > len(data) {
		var digest blake256.Digest
		digest.HashSize = blake256.Size * 8
		digest.Reset()
		_, _ = digest.Write(data[:])
		digest.Sum(data[:0])
		dataIndex = 0
	}
	return dataIndex
}
