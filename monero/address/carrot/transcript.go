package carrot

import (
	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

// HashedTranscript Equivalent to H_b(key, Transcript(...))
func HashedTranscript[S ~[]byte](dst S, hasher *blake2b.Digest, key []byte, domainSeparator []byte, args ...[]byte) {
	_ = hasher.Init(len(dst), key, nil, []byte(PersonalString))

	_, _ = hasher.Write([]byte{uint8(len(domainSeparator))})
	_, _ = hasher.Write(domainSeparator)
	for _, b := range args {
		_, _ = hasher.Write(b)
	}

	hasher.Sum(dst[:0])
}

// ScalarTranscript Equivalent to crypto.ScalarDerive(key, Transcript(...))
func ScalarTranscript(dst *curve25519.Scalar, hasher *blake2b.Digest, key []byte, domainSeparator []byte, args ...[]byte) {
	var h [blake2b.Size]byte
	HashedTranscript(h[:], hasher, key, domainSeparator, args...)

	curve25519.BytesToScalar64(dst, h)
}
