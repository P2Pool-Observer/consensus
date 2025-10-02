package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/sha3"
	"golang.org/x/crypto/blake2b"
)

func Keccak256(data ...[]byte) (result types.Hash) {
	h := sha3.NewLegacyKeccak256()
	for _, b := range data {
		_, _ = h.Write(b)
	}
	HashFastSum(h, result[:])

	return
}

func Keccak256Single(data []byte) (result types.Hash) {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(data)
	HashFastSum(h, result[:])

	return
}

func HashToScalar(data ...[]byte) *edwards25519.Scalar {
	h := PooledKeccak256(data...)

	c := GetEdwards25519Scalar()
	BytesToScalar32(h, c)

	return c
}

func HashToScalarNoAllocate(data ...[]byte) edwards25519.Scalar {
	h := Keccak256(data...)

	var c edwards25519.Scalar
	BytesToScalar32(h, &c)
	return c
}

func HashToScalarNoAllocateSingle(data []byte) edwards25519.Scalar {
	h := Keccak256Single(data)

	var c edwards25519.Scalar
	BytesToScalar32(h, &c)
	return c
}

// HashFastSum sha3.Sum clones the state by allocating memory. prevent that. b must be pre-allocated to the expected size, or larger
func HashFastSum(hash *sha3.HasherState, b []byte) []byte {
	_ = b[31] // bounds check hint to compiler; see golang.org/issue/14808
	_, _ = hash.Read(b[:types.HashSize])
	return b
}

// HopefulHashToPoint
// Defined as H_p^1 in Carrot
func HopefulHashToPoint(hasher *sha3.HasherState, data []byte) *edwards25519.Point {
	_, _ = hasher.Write(data[:])
	var h types.Hash
	HashFastSum(hasher, h[:])
	hasher.Reset()

	result := DecodeCompressedPoint(new(edwards25519.Point), h)
	if result == nil {
		return nil
	}

	// Ensure this point lies within the prime-order subgroup
	result.MultByCofactor(result)

	return result
}

// BiasedHashToPoint Monero's `hash_to_ec` / `biased_hash_to_ec` function.
// Defined as H_p^2 in Carrot
//
// Similar to https://github.com/monero-oxide/monero-oxide/blob/71be6f9180f78675dee7cab48fbee38134688574/monero-oxide/generators/src/hash_to_point.rs
//
// This achieves parity with https://github.com/monero-project/monero/blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto.cpp#L611, inlining the
// `ge_fromfe_frombytes_vartime` function (https://github.com/monero-project/monero/blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto-ops.c#L2309).
// This implementation runs in constant time.
//
// According to the original authors
// (https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf), this would
// implement https://arxiv.org/abs/0706.1448. Shen Noether also describes the algorithm
// (https://web.getmonero.org/resources/research-lab/pubs/ge_fromfe.pdf), yet without reviewing
// its security and in a very straight-forward fashion.
//
// In reality, this implements Elligator 2 as detailed in
// "Elligator: Elliptic-curve points indistinguishable from uniform random strings"
// (https://eprint.iacr.org/2013/325). Specifically, Section 5.5 details the application of
// Elligator 2 to Curve25519, after which the result is mapped to Ed25519.
//
// As this only applies Elligator 2 once, it's limited to a subset of points where a certain
// derivative of their `u` coordinates (in Montgomery form) are quadratic residues. It's biased
// accordingly.
func BiasedHashToPoint(hasher *sha3.HasherState, data []byte) *edwards25519.Point {
	_, _ = hasher.Write(data[:])
	var h types.Hash
	HashFastSum(hasher, h[:])
	hasher.Reset()

	result := elligator2WithUniformBytes(h)

	// Ensure points lie within the prime-order subgroup
	result.MultByCofactor(result)

	return result
}

// UnbiasedHashToPoint Monero's `unbiased_hash_to_ec` function.
// Defined as H_p^3 in FCMP++
//
// Similar to https://github.com/seraphis-migration/monero/blob/74a254f8c215986042c40e6875a0f97bd6169a1e/src/crypto/crypto.cpp#L622
func UnbiasedHashToPoint(preimage []byte) *edwards25519.Point {
	h := blake2b.Sum512(preimage)

	first := elligator2WithUniformBytes([32]byte(h[:32]))
	second := elligator2WithUniformBytes([32]byte(h[32:]))

	// Ensure points lie within the prime-order subgroup
	first.MultByCofactor(first)
	second.MultByCofactor(second)

	point := new(edwards25519.Point).Add(first, second)

	return point
}
