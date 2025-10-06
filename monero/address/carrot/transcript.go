package carrot

import (
	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

// HashedTranscript Equivalent to H_b(FixedTranscript(...))
func HashedTranscript[S ~[]byte](dst S, hasher *blake2b.Digest, key []byte, domainSeparator []byte, args ...[]byte) {
	_ = hasher.Init(len(dst), key, nil, nil)

	_, _ = hasher.Write([]byte{uint8(len(domainSeparator))})
	_, _ = hasher.Write(domainSeparator)
	for _, b := range args {
		_, _ = hasher.Write(b)
	}

	hasher.Sum(dst[:0])
}

// ScalarTranscript Equivalent to crypto.ScalarDerive(key, H_64(FixedTranscript(...)))
func ScalarTranscript(dst *edwards25519.Scalar, hasher *blake2b.Digest, key []byte, domainSeparator []byte, args ...[]byte) {
	var h [blake2b.Size]byte
	HashedTranscript(h[:], hasher, key, domainSeparator, args...)

	crypto.BytesToScalar64(h, dst)
}
