package circuit_abstraction

import "git.gammaspectra.live/P2Pool/blake2b"

type Transcript[F any] interface {
	Challenge(out *F) *F
	ChallengeBytes() (out [blake2b.Size]byte)
}
