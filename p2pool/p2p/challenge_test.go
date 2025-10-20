package p2p

import (
	"crypto/rand"
	"git.gammaspectra.live/P2Pool/consensus/v5/p2pool/sidechain"
	fasthex "github.com/tmthrgd/go-hex"
	"sync/atomic"
	"testing"
)

func TestFindChallengeSolution(t *testing.T) {
	var handshakeChallenge HandshakeChallenge
	if _, err := rand.Read(handshakeChallenge[:]); err != nil {
		t.Fatal(err)
	}

	var buf [1 + HandshakeChallengeSize]byte
	buf[0] = byte(MessageHandshakeChallenge)
	copy(buf[1:], handshakeChallenge[:])

	var stop atomic.Bool

	if solution, hash, ok := FindChallengeSolution(handshakeChallenge, sidechain.ConsensusDefault.Id, &stop); !ok {
		t.Fatalf("No solution for %s", fasthex.EncodeToString(handshakeChallenge[:]))
	} else {
		t.Logf("Solution for %s is %d (hash %s)", fasthex.EncodeToString(handshakeChallenge[:]), solution, hash.String())
	}
}
