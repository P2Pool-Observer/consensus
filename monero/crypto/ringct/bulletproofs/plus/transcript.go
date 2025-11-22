package plus

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

const DomainKeyTranscript = "bulletproof_plus_transcript"

var initialTranscriptHash = crypto.Keccak256(DomainKeyTranscript)

// initialTranscriptConstant Monero starts BP+ transcripts with the following constant.
// Why this uses a hash to point is completely unknown.
var initialTranscriptConstant = crypto.BiasedHashToPoint(new(curve25519.VarTimePublicKey), initialTranscriptHash[:]).AsBytes()

func InitialTranscript[T curve25519.PointOperations](out *curve25519.Scalar, commitments []curve25519.PublicKey[T]) *curve25519.Scalar {
	data := make([]byte, 0, len(commitments)*curve25519.PublicKeySize)
	for _, c := range commitments {
		data = append(data, c.Bytes()...)
	}
	crypto.ScalarDeriveLegacy(out, data)
	// this does scalar derive twice!
	crypto.ScalarDeriveLegacy(out, initialTranscriptConstant[:], out.Bytes())
	return out
}
