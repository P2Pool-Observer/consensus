package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// MerkleTree Used for block merkle root and similar
type MerkleTree []types.Hash

func leafHash(data []types.Hash, hasher KeccakHasher) (rootHash types.Hash) {
	switch len(data) {
	case 0:
		panic("unsupported length")
	case 1:
		return data[0]
	default:
		//only hash the next two items
		hasher.Reset()
		_, _ = hasher.Write(data[0][:])
		_, _ = hasher.Write(data[1][:])
		hasher.Hash(&rootHash)
		return rootHash
	}
}

func pairHash(index int, h, p types.Hash, hasher KeccakHasher) (out types.Hash) {
	hasher.Reset()

	if index&1 > 0 {
		_, _ = hasher.Write(p[:])
		_, _ = hasher.Write(h[:])
	} else {
		_, _ = hasher.Write(h[:])
		_, _ = hasher.Write(p[:])
	}

	hasher.Hash(&out)
	return out
}

// Depth The Merkle Tree depth
func (t MerkleTree) Depth() int {
	return utils.PreviousPowerOfTwo(uint64(len(t)))
}

// RootHash Calculates the Merkle root hash of the tree
func (t MerkleTree) RootHash() (rootHash types.Hash) {
	hasher := NewKeccak256()

	count := len(t)
	if count <= 2 {
		return leafHash(t, hasher)
	}

	depth := t.Depth()
	offset := depth*2 - count

	temporaryTree := make(MerkleTree, depth)
	copy(temporaryTree, t[:offset])

	//TODO: maybe can be done zero-alloc
	//temporaryTree := t[:max(depth, offset)]

	offsetTree := temporaryTree[offset:]
	for i := range offsetTree {
		offsetTree[i] = leafHash(t[offset+i*2:], hasher)
	}

	for depth >>= 1; depth > 1; depth >>= 1 {
		for i := range temporaryTree[:depth] {
			temporaryTree[i] = leafHash(temporaryTree[i*2:], hasher)
		}
	}

	rootHash = leafHash(temporaryTree, hasher)

	return
}

func (t MerkleTree) MainBranch() (mainBranch []types.Hash) {
	count := len(t)
	if count <= 2 {
		return nil
	}

	hasher := NewKeccak256()

	depth := t.Depth()
	offset := depth*2 - count

	temporaryTree := make(MerkleTree, depth)
	copy(temporaryTree, t[:offset])

	offsetTree := temporaryTree[offset:]

	for i := range offsetTree {
		if (offset + i*2) == 0 {
			mainBranch = append(mainBranch, t[1])
		}
		offsetTree[i] = leafHash(t[offset+i*2:], hasher)
	}

	for depth >>= 1; depth > 1; depth >>= 1 {
		for i := range temporaryTree[:depth] {
			if i == 0 {
				mainBranch = append(mainBranch, temporaryTree[1])
			}

			temporaryTree[i] = leafHash(temporaryTree[i*2:], hasher)
		}
	}

	mainBranch = append(mainBranch, temporaryTree[1])

	return
}

type MerkleProof []types.Hash

// Verify Verifies a merkle proof with the slot index and chain count
// Equivalent to verify_merkle_proof(aux_hash, merkle_proof, get_aux_slot(unique_id, aux_nonce, n_aux_chains), n_aux_chains, merkle_root_hash)
func (proof MerkleProof) Verify(h types.Hash, index, count int, rootHash types.Hash) bool {
	return proof.GetRoot(h, index, count) == rootHash
}

// VerifyPath Verifies a merkle proof with the path bitmap
// verify_merkle_proof(aux_hash, merkle_proof, path, merkle_root_hash)
func (proof MerkleProof) VerifyPath(h types.Hash, path uint32, rootHash types.Hash) bool {
	return proof.GetRootPath(h, path) == rootHash
}

func (proof MerkleProof) GetRoot(h types.Hash, index, count int) types.Hash {
	if count == 1 {
		return h
	}

	if index >= count {
		return types.ZeroHash
	}

	hasher := NewKeccak256()

	if count == 2 {
		if len(proof) == 0 {
			return types.ZeroHash
		}

		h = pairHash(index, h, proof[0], hasher)
	} else {
		pow2cnt := utils.PreviousPowerOfTwo(uint64(count))
		k := pow2cnt*2 - count

		var proofIndex int

		if index >= k {
			index -= k

			if len(proof) == 0 {
				return types.ZeroHash
			}

			h = pairHash(index, h, proof[0], hasher)

			index = (index >> 1) + k
			proofIndex = 1

		}

		for ; pow2cnt >= 2; proofIndex, index, pow2cnt = proofIndex+1, index>>1, pow2cnt>>1 {
			if proofIndex >= len(proof) {
				return types.ZeroHash
			}

			h = pairHash(index, h, proof[proofIndex], hasher)
		}
	}

	return h
}

func (proof MerkleProof) GetRootPath(h types.Hash, path uint32) types.Hash {
	hasher := NewKeccak256()

	depth := len(proof)

	if depth == 0 {
		return h
	}

	for d := 0; d < depth; d++ {
		h = pairHash(int(path>>(depth-d-1)), h, proof[d], hasher)
	}
	return h
}
