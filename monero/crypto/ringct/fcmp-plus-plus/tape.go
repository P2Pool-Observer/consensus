package fcmp_plus_plus

import (
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	ec_gadgets "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus/ec-gadgets"
	gb "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

const COMMITMENT_WORD_LEN = 128

type VectorCommitmentTape[F Field, FE curve.BasicField[F]] struct {
	CommitmentLen  int
	CurrentJOffset int
	Commitments    [][]F
	BranchLengths  []int
}

// Append a series of variables to the vector commitment tape.
func (t *VectorCommitmentTape[F, FE]) Append(variables []F) (res []gb.Variable) {
	if variables != nil {
		if len(variables) != COMMITMENT_WORD_LEN {
			panic("unreachable")
		}
	}

	if t.CurrentJOffset == 0 {
		t.Commitments = append(t.Commitments, variables)
	} else {
		t.Commitments[len(t.Commitments)-1] = append(t.Commitments[len(t.Commitments)-1], variables...)
	}

	i := len(t.Commitments) - 1
	for j := t.CurrentJOffset; j < t.CurrentJOffset+COMMITMENT_WORD_LEN; j++ {
		res = append(res, gb.VariableCG{Commitment: i, Index: j})
	}

	t.CurrentJOffset += COMMITMENT_WORD_LEN
	if t.CurrentJOffset == t.CommitmentLen {
		t.CurrentJOffset = 0
	}
	return res
}

func (t *VectorCommitmentTape[F, FE]) AppendBranch(branchLen int, branch []F) (branchVariables []gb.Variable) {
	if len(branch) != branchLen {
		panic("unreachable")
	}
	if t.CurrentJOffset != 0 {
		panic("unreachable")
	}
	if len(t.BranchLengths) != len(t.Commitments) {
		panic("unreachable")
	}
	t.BranchLengths = append(t.BranchLengths, branchLen)
	if branchLen == 0 || branchLen > t.CommitmentLen {
		panic("unreachable")
	}

	wordsInBranch := utils.DivCeil(branchLen, COMMITMENT_WORD_LEN)

	empty := make([]F, COMMITMENT_WORD_LEN)
	for i := range empty {
		FE(&empty[i]).Zero()
	}

	branch = slices.Clone(branch)
	for len(branch)%COMMITMENT_WORD_LEN != 0 {
		// pad the branch
		branch = append(branch, *FE(new(F)).Zero())
	}

	// Append each chunk of the branch
	branchVariables = make([]gb.Variable, 0, branchLen)
	for b := range wordsInBranch {
		branchVariables = append(branchVariables, t.Append(branch[b*COMMITMENT_WORD_LEN:(b+1)*COMMITMENT_WORD_LEN])...)
	}

	// Truncate any padding we created a variable for
	branchVariables = branchVariables[:branchLen]

	// Append padding to this vector commitment so nothing else is added to this
	for i := wordsInBranch; i < t.CommitmentLen/COMMITMENT_WORD_LEN; i++ {
		t.Append(empty)
	}
	return branchVariables
}

func (t *VectorCommitmentTape[F, FE]) AppendDlog[FFE curve.Field[F]](params ec_gadgets.Parameters, dlog []uint64, padding []F, extra *F) ([]gb.Variable, []gb.Variable, gb.Variable) {
	dlogBits := params.ScalarBits

	var witness []F
	if len(dlog) > 0 {
		witness = make([]F, 0, 256)
		if len(dlog) != dlogBits {
			panic("unreachable")
		}
		for _, coeff := range dlog {
			witness = append(witness, *curve.FieldFromUint64[F, FFE](new(F), coeff))
		}

		if len(padding) > (255 - dlogBits) {
			panic("unreachable")
		}

		for i := range 255 - dlogBits {
			if len(padding) > i {
				witness = append(witness, padding[i])
			} else {
				witness = append(witness, *FE(new(F)).Zero())
			}
		}

		if len(witness) != 255 {
			panic("unreachable")
		}

		// Since we have an extra slot, push an extra item
		witness = append(witness, *extra)
	}

	var witnessA, witnessB []F
	if len(witness) > 0 {
		witnessA = witness[:COMMITMENT_WORD_LEN]
		witnessB = witness[COMMITMENT_WORD_LEN:]
	}

	variables := t.Append(witnessA)
	variables = append(variables, t.Append(witnessB)...)

	{
		extra := variables[len(variables)-1]
		padding := variables[dlogBits:255]
		dlog := variables[:dlogBits]

		return dlog, padding, extra
	}
}
