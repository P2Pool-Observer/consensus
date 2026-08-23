package generalized_bulletproofs

import (
	"bytes"
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

const (
	DomainScalar    = 0
	DomainPoint     = 1
	DomainChallenge = 2
)

func Challenge[F any, FE curve.Field[F]](hasher *blake2b.Digest, out *F) *F {
	_, _ = utils.WriteNoEscape(hasher, []byte{DomainChallenge})
	var sum [blake2b.Size]byte
	utils.SumNoEscape(hasher, sum[:0])

	out, _ = FE(out).SetWideBytes(sum[:])

	if FE(out).IsZero() == 1 {
		panic("zero challenge")
	}

	return out
}

type Commitments[P any, F any, PE curve.ExtraCurvePoint[P, F]] struct {
	C PointVector[P, F, PE]
	V PointVector[P, F, PE]
}
type Transcript[P any, F any] struct {
	digest     blake2b.Digest
	transcript []byte
}

func NewTranscript[P any, F any](context [32]byte) *Transcript[P, F] {
	var t Transcript[P, F]
	_ = t.digest.Init(blake2b.Size, nil, nil, nil)
	_, _ = utils.WriteNoEscape(&t.digest, context[:])
	t.transcript = make([]byte, 0, 1024)
	return &t
}

func (t *Transcript[P, F]) PushScalar[FE curve.Field[F]](scalar *F) {
	_, _ = utils.WriteNoEscape(&t.digest, []byte{DomainScalar})
	buf := FE(scalar).Bytes()
	_, _ = utils.WriteNoEscape(&t.digest, buf)
	t.transcript = append(t.transcript, buf...)
}

func (t *Transcript[P, F]) PushPoint[PE curve.ExtraCurvePoint[P, F]](point *P) {
	_, _ = utils.WriteNoEscape(&t.digest, []byte{DomainPoint})
	buf := PE(point).Bytes()
	_, _ = utils.WriteNoEscape(&t.digest, buf)
	t.transcript = append(t.transcript, buf...)
}

func (t *Transcript[P, F]) WriteCommitments[PE curve.ExtraCurvePoint[P, F]](c, v []P) Commitments[P, F, PE] {
	var buf [8]byte

	binary.LittleEndian.PutUint64(buf[:], uint64(len(c)))
	_, _ = utils.WriteNoEscape(&t.digest, buf[:])
	for i := range c {
		t.PushPoint[PE](&c[i])
	}

	binary.LittleEndian.PutUint64(buf[:], uint64(len(v)))
	_, _ = utils.WriteNoEscape(&t.digest, buf[:])
	for i := range v {
		t.PushPoint[PE](&v[i])
	}
	return Commitments[P, F, PE]{
		C: c,
		V: v,
	}
}

func (t *Transcript[P, F]) Challenge[FE curve.Field[F]](out *F) *F {
	return Challenge[F, FE](&t.digest, out)
}

func (t *Transcript[P, F]) ChallengeBytes() (out [blake2b.Size]byte) {
	_, _ = utils.WriteNoEscape(&t.digest, []byte{DomainChallenge})
	utils.SumNoEscape(&t.digest, out[:0])
	return out
}

func (t *Transcript[P, F]) Complete() []byte {
	return t.transcript
}

type VerifierTranscript[P any, F any] struct {
	digest     blake2b.Digest
	buf        []byte
	transcript bytes.Reader
}

func NewVerifierTranscript[P any, F any](context [32]byte, proof []byte) *VerifierTranscript[P, F] {
	var t VerifierTranscript[P, F]
	_ = t.digest.Init(blake2b.Size, nil, nil, nil)
	_, _ = utils.WriteNoEscape(&t.digest, context[:])
	t.buf = proof
	t.transcript.Reset(t.buf)
	return &t
}

func (t *VerifierTranscript[P, F]) ReadScalar[FE curve.Field[F]](out *F) (*F, error) {
	_, _ = utils.WriteNoEscape(&t.digest, []byte{DomainScalar})
	var buf [32]byte
	if _, err := utils.ReadFullNoEscape(&t.transcript, buf[:]); err != nil {
		return nil, err
	}
	_, _ = utils.WriteNoEscape(&t.digest, buf[:])
	return FE(out).SetBytes(buf[:])
}

func (t *VerifierTranscript[P, F]) ReadPoint[PE curve.ExtraCurvePoint[P, F]](out *P) (*P, error) {
	_, _ = utils.WriteNoEscape(&t.digest, []byte{DomainPoint})
	var buf [32]byte
	if _, err := utils.ReadFullNoEscape(&t.transcript, buf[:]); err != nil {
		return nil, err
	}
	_, _ = utils.WriteNoEscape(&t.digest, buf[:])
	return PE(out).SetBytes(buf[:])
}

func (t *VerifierTranscript[P, F]) ReadCommitments[PE curve.ExtraCurvePoint[P, F]](c, v int) (*Commitments[P, F, PE], error) {

	var tmp P
	var buf [8]byte

	binary.LittleEndian.PutUint64(buf[:], uint64(c))
	_, _ = utils.WriteNoEscape(&t.digest, buf[:])
	C := make([]P, 0, c)
	for range c {
		if p, err := t.ReadPoint[PE](&tmp); err != nil {
			return nil, err
		} else {
			C = append(C, *p)
		}
	}

	binary.LittleEndian.PutUint64(buf[:], uint64(v))
	_, _ = utils.WriteNoEscape(&t.digest, buf[:])
	V := make([]P, 0, v)
	for range v {
		if p, err := t.ReadPoint[PE](&tmp); err != nil {
			return nil, err
		} else {
			V = append(V, *p)
		}
	}

	return &Commitments[P, F, PE]{
		C: C,
		V: V,
	}, nil
}

func (t *VerifierTranscript[P, F]) Challenge[FE curve.Field[F]](out *F) *F {
	return Challenge[F, FE](&t.digest, out)
}

func (t *VerifierTranscript[P, F]) ChallengeBytes() (out [blake2b.Size]byte) {
	_, _ = utils.WriteNoEscape(&t.digest, []byte{DomainChallenge})
	utils.SumNoEscape(&t.digest, out[:0])
	return out
}

func (t *VerifierTranscript[P, F]) Complete() []byte {
	return t.buf[len(t.buf)-t.transcript.Len():]
}
