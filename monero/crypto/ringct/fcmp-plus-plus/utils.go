package fcmp_plus_plus

import (
	"encoding/binary"

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

func PrefixWeightV1(inputs, outputs, extra int) int {
	const txin_to_key_weight = 1 /*amount=0*/ + 1 /*key_offsets.size()=0*/ + 32 /*k_image*/
	const txout_to_carrot_weight = 32 /*key*/ + 3 /*view_tag*/ + 16             /*encrypted_janus_anchor*/
	const tx_out_weight = 1 /*amount=0*/ + txout_to_carrot_weight + 1           /*txout_target_v tag*/

	return 1 /*version=2*/ +
		1 /*unlock_time=0*/ +
		utils.UVarInt64Size(inputs) /*vin.size()<=FCMP_PLUS_PLUS_MAX_INPUTS*/ +
		inputs*(txin_to_key_weight /*txin_to_key*/ +1 /*txin_v tag*/) +
		1 /*vout.size()<=FCMP_PLUS_PLUS_MAX_OUTPUTS*/ +
		(outputs * tx_out_weight /*tx_out*/) +
		utils.UVarInt64Size(extra) /*extra.size()*/ +
		extra
}

func UnprunableWeightV1(inputs, outputs, extra int) int {
	const rct_sig_base_per_out_weight = 8 /*ecdhInfo.at(i).amount*/ + 32 /*outPk.at(i).mask*/
	return PrefixWeightV1(inputs, outputs, extra) +
		1 /*type*/ +
		binary.MaxVarintLen64 /*txnFee*/ +
		(outputs * rct_sig_base_per_out_weight)
}

func TransactionWeightV1(inputs, outputs, extra int) int {
	unprunableWeight := UnprunableWeightV1(inputs, outputs, extra)
	const max_block_index_varint_len = binary.MaxVarintLen32            // size of varint storing CRYPTONOTE_MAX_BLOCK_NUMBER
	const rerandomized_output_weight = FCMP_PP_INPUT_TUPLE_SIZE_V1 + 32 /*C~ AKA pseudoOut*/

	totalSALWeight := inputs * (rerandomized_output_weight + FCMP_PP_SAL_PROOF_SIZE_V1)
	const miscFCMPPlusPlusWeight = max_block_index_varint_len + 1

	// Calculate deterministic bulletproofs size (assumes canonical BP format)
	nrl := 0
	paddedOutputs := 1
	for paddedOutputs < outputs {
		paddedOutputs <<= 1
		nrl++
	}
	nrl += 6
	bpWeight := 32*(6+2*nrl) + 2
	bpWeight++ /*nbp*/

	// There's a few reasons why we treat n_tree_layers as a fixed value for weight calculation:
	//     a. If we took n_tree_layers into account when calculating weight, then fee calculation
	//        would be a function of the number of layers in the FCMP tree. This has a couple
	//        implications:
	//            i.  To determine the "correct" fee in multi-signer/cold-signer contexts, signers
	//                would have to transmit and agree upon what the current n_tree_layers value is,
	//                which complicates these protocols, and is inherently difficult to validate
	//                for offline signers. It also just complicates the process for normal wallets.
	//            ii. If signers need guarantees that a signature for a transaction proposal with a
	//                certain fee isn't reused for similar transaction but with a different
	//                n_tree_layers, and thus weight, then n_tree_layers would have to be included
	//                in rctSigBase and hashed into the signable_tx_hash, which means an extra byte
	//                per pruned transaction when wallets are refreshing. Also, more subjectively,
	//                putting n_tree_layers into rctSigBase feels misplaced.
	//     b. Dropping the weight for low values of n_tree_layers directly incentivizes spenders of
	//        old enotes to use as small a value of n_tree_layers as possible, which hurts their
	//        anonymity.
	//
	// We chose 7 specifically because at the time of writing (9 April 2025), the current layer size
	// of the Monero mainnet would be 6. 7 is approaching relatively quickly, and would be the value
	// for many decades at the current tx volume.
	const fake_n_tree_layers = 7

	fcmpWeight := MembershipProofSize(inputs, fake_n_tree_layers)
	rctSigPrunableWeight := bpWeight + totalSALWeight + miscFCMPPlusPlusWeight + fcmpWeight

	return unprunableWeight + rctSigPrunableWeight
}
