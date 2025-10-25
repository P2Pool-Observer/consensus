package crypto

import (
	"hash"
	"io"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"golang.org/x/crypto/sha3"
)

type HashReader interface {
	hash.Hash
	io.Reader
}

type KeccakHasher struct {
	h HashReader
}

func (k KeccakHasher) Read(p []byte) (n int, err error) {
	return utils.ReadNoEscape(k.h, p)
}

func (k KeccakHasher) Write(p []byte) (n int, err error) {
	return utils.WriteNoEscape(k.h, p)
}

func (k KeccakHasher) Sum(b []byte) []byte {
	return utils.SumNoEscape(k.h, b)
}

func (k KeccakHasher) Hash(h *types.Hash) {
	_, _ = utils.ReadNoEscape(k.h, h[:])
}

func (k KeccakHasher) Reset() {
	utils.ResetNoEscape(k.h)
}

func (k KeccakHasher) Size() int {
	return k.h.Size()
}

func (k KeccakHasher) BlockSize() int {
	return k.h.BlockSize()
}

//go:nosplit
func NewKeccak256() KeccakHasher {
	return KeccakHasher{h: sha3.NewLegacyKeccak256().(HashReader)}
}

//go:nosplit
func newKeccak256() HashReader {
	return sha3.NewLegacyKeccak256().(HashReader)
}

func Keccak256Var[T ~string | ~[]byte](data ...T) (result types.Hash) {
	h := newKeccak256()
	for _, b := range data {
		_, _ = utils.WriteNoEscape(h, []byte(b))
	}
	_, _ = utils.ReadNoEscape(h, result[:types.HashSize])

	return
}

func Keccak256[T ~string | ~[]byte](data T) (result types.Hash) {
	h := newKeccak256()
	_, _ = utils.WriteNoEscape(h, []byte(data))
	_, _ = utils.ReadNoEscape(h, result[:types.HashSize])

	return
}

func TransactionIdHash(dst *types.Hash, coinbaseBlobMinusBaseRTC, baseRTC, prunableRTC types.Hash) {
	h := newKeccak256()
	_, _ = utils.WriteNoEscape(h, coinbaseBlobMinusBaseRTC[:])
	_, _ = utils.WriteNoEscape(h, baseRTC[:])
	_, _ = utils.WriteNoEscape(h, prunableRTC[:])
	_, _ = utils.ReadNoEscape(h, dst[:])
}

// HopefulHashToPoint
// Defined as H_p^1 in Carrot
func HopefulHashToPoint(dst *edwards25519.Point, data []byte) *edwards25519.Point {
	result := DecodeCompressedPoint(dst, Keccak256(data))
	if result == nil {
		return nil
	}

	// Ensure this point lies within the prime-order subgroup
	result.MultByCofactor(result)

	return result
}

// BiasedHashToPoint Monero's `hash_to_ec` / `biased_hash_to_ec` function.
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
func BiasedHashToPoint(dst *edwards25519.Point, data []byte) *edwards25519.Point {
	elligator2WithUniformBytes(dst, Keccak256(data))

	// Ensure points lie within the prime-order subgroup
	dst.MultByCofactor(dst)
	return dst
}

// UnbiasedHashToPoint Monero's `unbiased_hash_to_ec` function.
// Defined as H_p^2 in Carrot
//
// Similar to https://github.com/seraphis-migration/monero/blob/74a254f8c215986042c40e6875a0f97bd6169a1e/src/crypto/crypto.cpp#L622
func UnbiasedHashToPoint(dst *edwards25519.Point, preimage []byte) *edwards25519.Point {
	h := blake2b.Sum512(preimage)

	var first, second edwards25519.Point
	elligator2WithUniformBytes(&first, [PublicKeySize]byte(h[:PublicKeySize]))
	elligator2WithUniformBytes(&second, [PublicKeySize]byte(h[PublicKeySize:]))

	// Ensure points lie within the prime-order subgroup
	first.MultByCofactor(&first)
	second.MultByCofactor(&second)

	dst.Add(&first, &second)
	return dst
}
