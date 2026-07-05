package crypto

import (
	"encoding/binary"
	"math/bits"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/sha3"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// MerkleTree Used for block merkle root and similar
type MerkleTree []types.Hash

func pairHash(index int, h, p types.Hash, hasher *sha3.Digest) (out types.Hash) {
	hasher.Reset()

	if index&1 > 0 {
		_, _ = hasher.Write(p[:])
		_, _ = hasher.Write(h[:])
	} else {
		_, _ = hasher.Write(h[:])
		_, _ = hasher.Write(p[:])
	}

	_, _ = hasher.Read(out[:])
	return out
}

func singleHash(out, a, b *types.Hash, hasher *sha3.Digest) {
	hasher.Reset()

	_, _ = hasher.Write(a[:])
	_, _ = hasher.Write(b[:])

	_, _ = hasher.Read(out[:])
}

func quadHash(st *[4 * 25]uint64, in *[8]types.Hash, out *[4]types.Hash) {
	*st = [4 * 25]uint64{}
	for i := range 4 {
		a, b := &in[2*i], &in[2*i+1]
		st[0+i] = binary.LittleEndian.Uint64(a[0:])
		st[4+i] = binary.LittleEndian.Uint64(a[8:])
		st[8+i] = binary.LittleEndian.Uint64(a[16:])
		st[12+i] = binary.LittleEndian.Uint64(a[24:])
		st[16+i] = binary.LittleEndian.Uint64(b[0:])
		st[20+i] = binary.LittleEndian.Uint64(b[8:])
		st[24+i] = binary.LittleEndian.Uint64(b[16:])
		st[28+i] = binary.LittleEndian.Uint64(b[24:])
		st[32+i] = 0x01
		st[64+i] = 0x80 << 56
	}

	sha3.KeccakF1600x4(st)
	for i := range 4 {
		o := &out[i]
		binary.LittleEndian.PutUint64(o[0:], st[0+i])
		binary.LittleEndian.PutUint64(o[8:], st[4+i])
		binary.LittleEndian.PutUint64(o[16:], st[8+i])
		binary.LittleEndian.PutUint64(o[24:], st[12+i])
	}
}

func quadHashN(st *[4 * 25]uint64, s []types.Hash, i, k int) {
	*st = [4 * 25]uint64{}
	for l := range k {
		a, b := &s[2*(i+l)], &s[2*(i+l)+1]
		st[0+l] = binary.LittleEndian.Uint64(a[0:])
		st[4+l] = binary.LittleEndian.Uint64(a[8:])
		st[8+l] = binary.LittleEndian.Uint64(a[16:])
		st[12+l] = binary.LittleEndian.Uint64(a[24:])
		st[16+l] = binary.LittleEndian.Uint64(b[0:])
		st[20+l] = binary.LittleEndian.Uint64(b[8:])
		st[24+l] = binary.LittleEndian.Uint64(b[16:])
		st[28+l] = binary.LittleEndian.Uint64(b[24:])
		st[32+l] = 0x01
		st[64+l] = 0x80 << 56
	}

	sha3.KeccakF1600x4(st)
	for l := range k {
		o := &s[i+l]
		binary.LittleEndian.PutUint64(o[0:], st[0+l])
		binary.LittleEndian.PutUint64(o[8:], st[4+l])
		binary.LittleEndian.PutUint64(o[16:], st[8+l])
		binary.LittleEndian.PutUint64(o[24:], st[12+l])
	}
}

func reduce(s []types.Hash, n int, st *[4 * 25]uint64, hasher *sha3.Digest) {
	if !sha3.KeccakX4Supported {
		for i := range n {
			singleHash(&s[i], &s[2*i], &s[2*i+1], hasher)
		}
		return
	}

	i := 0

	for ; i+4 <= n; i += 4 {
		quadHash(st, (*[8]types.Hash)(s[2*i:]), (*[4]types.Hash)(s[i:]))
	}

	switch n - i {
	case 0:
	case 1:
		singleHash(&s[i], &s[2*i], &s[2*i+1], hasher)
	default:
		quadHashN(st, s, i, n-i)
	}
}

// Depth The Merkle Tree depth
func (t MerkleTree) Depth() int {
	return utils.PreviousPowerOfTwo(uint64(len(t)))
}

// RootHash Calculates the Merkle root hash of the tree
//
// Note: t is mutated in-place
func (t MerkleTree) RootHash() (rootHash types.Hash) {
	count := len(t)
	if count == 1 {
		return t[0]
	}

	hasher := NewKeccak256()

	if count == 2 {
		singleHash(&rootHash, &t[0], &t[1], hasher)
		return rootHash
	}

	var state [4 * 25]uint64

	depth := t.Depth()
	offset := depth*2 - count

	reduce(t[offset:], depth-offset, &state, hasher)

	for size := depth; size > 1; size >>= 1 {
		reduce(t, size>>1, &state, hasher)
	}
	return t[0]
}

// MainBranch Calculates the Merkle tree main branch
//
// Note: t is mutated in-place
func (t MerkleTree) MainBranch() (mainBranch []types.Hash) {
	count := len(t)
	if count <= 2 {
		return nil
	}

	hasher := NewKeccak256()

	var state [4 * 25]uint64

	depth := t.Depth()
	offset := depth*2 - count

	mainBranch = make([]types.Hash, 0, bits.Len(uint(depth)))
	if offset == 0 {
		mainBranch = append(mainBranch, t[1])
	}

	reduce(t[offset:], depth-offset, &state, hasher)
	for size := depth; size > 1; size >>= 1 {
		mainBranch = append(mainBranch, t[1])
		reduce(t, size>>1, &state, hasher)
	}
	return mainBranch
}

type MerkleProof []types.Hash

// Verify Verifies a merkle proof with the slot index and chain count
// Equivalent to verify_merkle_proof(aux_hash, merkle_proof, get_aux_slot(unique_id, aux_nonce, n_aux_chains), n_aux_chains, merkle_root_hash)
func (proof MerkleProof) Verify(h types.Hash, index, count int, rootHash types.Hash) bool {
	root, ok := proof.GetRoot(h, index, count)
	return ok && root == rootHash
}

// VerifyPath Verifies a merkle proof with the path bitmap
// verify_merkle_proof(aux_hash, merkle_proof, path, merkle_root_hash)
func (proof MerkleProof) VerifyPath(h types.Hash, path uint32, rootHash types.Hash) bool {
	return proof.GetRootPath(h, path) == rootHash
}

func (proof MerkleProof) GetRoot(h types.Hash, index, count int) (root types.Hash, ok bool) {
	if count == 1 {
		return h, len(proof) == 0
	}

	if index >= count {
		return types.ZeroHash, false
	}

	hasher := NewKeccak256()

	if count == 2 {
		if len(proof) != 1 {
			return types.ZeroHash, false
		}

		h = pairHash(index, h, proof[0], hasher)
	} else {
		pow2cnt := utils.PreviousPowerOfTwo(uint64(count))
		k := pow2cnt*2 - count

		var proofIndex int

		if index >= k {
			index -= k

			if len(proof) == 0 {
				return types.ZeroHash, false
			}

			h = pairHash(index, h, proof[0], hasher)

			index = (index >> 1) + k
			proofIndex = 1

		}

		for ; pow2cnt >= 2; proofIndex, index, pow2cnt = proofIndex+1, index>>1, pow2cnt>>1 {
			if proofIndex >= len(proof) {
				return types.ZeroHash, false
			}

			h = pairHash(index, h, proof[proofIndex], hasher)
		}

		if proofIndex != len(proof) {
			return types.ZeroHash, false
		}
	}

	return h, true
}

func (proof MerkleProof) GetRootPath(h types.Hash, path uint32) types.Hash {
	hasher := NewKeccak256()

	depth := len(proof)

	if depth == 0 {
		return h
	}

	for d := range depth {
		h = pairHash(int(path>>(depth-d-1)), h, proof[d], hasher)
	}
	return h
}
