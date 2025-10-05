package carrot

import (
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"golang.org/x/crypto/blake2b"
)

func FixedTranscript(domainSeparator []byte, args ...[]byte) []byte {
	//todo: proper size
	result := make([]byte, 0, 1+len(domainSeparator)+len(args)*32)

	result = append(result, uint8(len(domainSeparator)))
	result = append(result, domainSeparator...)
	for _, arg := range args {
		result = append(result, arg...)
	}
	return result
}

// HashedTranscript Equivalent to H_b(FixedTranscript(...))
func HashedTranscript[S ~[]byte](dst S, key []byte, domainSeparator []byte, args ...[]byte) {
	hasher, _ := blake2b.New(len(dst), key)
	if hasher == nil {
		panic("unreachable")
	}
	_, _ = utils.WriteNoEscape(hasher, []byte{uint8(len(domainSeparator))})
	_, _ = utils.WriteNoEscape(hasher, domainSeparator)
	for _, b := range args {
		_, _ = utils.WriteNoEscape(hasher, b)
	}

	utils.SumNoEscape(hasher, dst[:0])
}

// ScalarTranscript Equivalent to crypto.ScalarDerive(key, H_64(FixedTranscript(...)))
func ScalarTranscript(dst *edwards25519.Scalar, key []byte, domainSeparator []byte, args ...[]byte) {
	hasher, _ := blake2b.New512(key)
	if hasher == nil {
		panic("unreachable")
	}
	_, _ = utils.WriteNoEscape(hasher, []byte{uint8(len(domainSeparator))})
	_, _ = utils.WriteNoEscape(hasher, domainSeparator)
	for _, b := range args {
		_, _ = utils.WriteNoEscape(hasher, b)
	}

	var h [blake2b.Size]byte
	utils.SumNoEscape(hasher, h[:0])

	crypto.BytesToScalar64(h, dst)
}
