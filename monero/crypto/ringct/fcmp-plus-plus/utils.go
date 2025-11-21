package fcmp_plus_plus

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// LAYER_ONE_LEN The length of branches proved for on the first layer.
//
// The leaves' layer is six times as wide.
const LAYER_ONE_LEN = 38

// LAYER_TWO_LEN The length of branches proved for on the second layer.
const LAYER_TWO_LEN = 18

const C1_LEAVES_ROWS_PER_INPUT = 97
const C1_BRANCH_ROWS_PER_INPUT = 52
const C2_ROWS_PER_INPUT_PER_LAYER = 32
const C1_TARGET_ROWS = 256
const C2_TARGET_ROWS = 128

// MaxInputs The maximum amount of input tuples provable for within a single FCMP.
//
// https://github.com/seraphis-migration/monero/blob/8bf178a3009ee066001189d05869445bdf4ed28c/src/cryptonote_config.h#L217
const MaxInputs = 128

// MaxLayers The maximum amount of layers supported within a FCMP.
//
// The FCMP itself theoretically supports an unbounded amount of layers, with exponential growth
// in set size as additional layers are added. The size of the proof (for each input) still grows
// linearly with the amount of layers, requiring a sufficiently-large constant reference string.
// This constant is used to generate the constant reference string, and it's that which bounds the
// amount of layers supported.
//
// Theoretically, the generators could be dynamically built/extended at runtime to remove this
// limit, yet this offers such a large set size it will never be reached.
//
// https://github.com/seraphis-migration/monero/blob/8bf178a3009ee066001189d05869445bdf4ed28c/src/cryptonote_config.h#L222
const MaxLayers = 12

// IPARows Returns how many rows would be used in each of the two IPAs.
func IPARows(inputs, layers int) (int, int) {
	non_leaves_c1_branches := (layers - 1) / 2
	c1_rows := inputs * (C1_LEAVES_ROWS_PER_INPUT + (non_leaves_c1_branches * C1_BRANCH_ROWS_PER_INPUT))

	c2_branches := layers / 2
	c2_rows := inputs * max(c2_branches*C2_ROWS_PER_INPUT_PER_LAYER, 1)

	c1_rows = utils.NextPowerOfTwo(uint(c1_rows))
	c2_rows = utils.NextPowerOfTwo(uint(c2_rows))
	return max(c1_rows, C1_TARGET_ROWS), max(c2_rows, C2_TARGET_ROWS)
}
