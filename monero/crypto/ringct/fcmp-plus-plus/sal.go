package fcmp_plus_plus

import (
	"io"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/multiexp"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type SpendAuthAndLinkability[T curve25519.PointOperations] struct {
	P   curve25519.PublicKey[T]
	A   curve25519.PublicKey[T]
	B   curve25519.PublicKey[T]
	R_O curve25519.PublicKey[T]
	R_P curve25519.PublicKey[T]
	R_L curve25519.PublicKey[T]

	SAlpha curve25519.Scalar
	SBeta  curve25519.Scalar
	SDelta curve25519.Scalar
	SY     curve25519.Scalar
	SZ     curve25519.Scalar
	SR_P   curve25519.Scalar
}

func (sal *SpendAuthAndLinkability[T]) Challenge(dst *curve25519.Scalar, signableTxHash types.Hash, input *Input[T], L *curve25519.PublicKey[T]) {
	var transcript blake2b.Digest
	_ = transcript.Init(blake2b.Size, nil, nil, nil)

	_, _ = transcript.Write(signableTxHash[:])
	input.Transcript(&transcript, L)
	_, _ = transcript.Write(sal.P.Bytes())
	_, _ = transcript.Write(sal.A.Bytes())
	_, _ = transcript.Write(sal.B.Bytes())
	_, _ = transcript.Write(sal.R_O.Bytes())
	_, _ = transcript.Write(sal.R_P.Bytes())
	_, _ = transcript.Write(sal.R_L.Bytes())

	var h [blake2b.Size]byte
	transcript.Sum(h[:0])

	curve25519.BytesToScalar64(dst, h)
}

func (sal *SpendAuthAndLinkability[T]) Verify(verifier *multiexp.BatchVerifier[struct{}, T], signableTxHash types.Hash, input *Input[T], L *curve25519.PublicKey[T], randomReader io.Reader) {

	var e curve25519.Scalar
	sal.Challenge(&e, signableTxHash, input, L)

	// BP+ Verification Statement
	verifier.Queue(struct{}{}, []multiexp.ScalarPointPair[T]{
		{*new(curve25519.Scalar).Multiply(&e, &e), sal.P},
		{e, sal.A},
		{*new(curve25519.Scalar).One(), sal.B},

		// RHS
		{*new(curve25519.Scalar).Negate(new(curve25519.Scalar).Multiply(&sal.SAlpha, &e)), *curve25519.FromPoint[T](crypto.GeneratorG.Point)},
		{*new(curve25519.Scalar).Negate(new(curve25519.Scalar).Multiply(&sal.SBeta, &e)), *curve25519.FromPoint[T](crypto.GeneratorV.Point)},
		{*new(curve25519.Scalar).Negate(new(curve25519.Scalar).Multiply(&sal.SAlpha, &sal.SBeta)), *curve25519.FromPoint[T](crypto.GeneratorU.Point)},
		{*new(curve25519.Scalar).Negate(&sal.SDelta), *curve25519.FromPoint[T](crypto.GeneratorT.Point)},
	}, randomReader)

	// O_tilde GSP Verification Statement
	verifier.Queue(struct{}{}, []multiexp.ScalarPointPair[T]{
		{*new(curve25519.Scalar).One(), sal.R_O},
		{e, input.OTilde},

		// RHS
		{*new(curve25519.Scalar).Negate(&sal.SAlpha), *curve25519.FromPoint[T](crypto.GeneratorG.Point)},
		{*new(curve25519.Scalar).Negate(&sal.SY), *curve25519.FromPoint[T](crypto.GeneratorT.Point)},
	}, randomReader)

	// P' GSP Verification Statement
	verifier.Queue(struct{}{}, []multiexp.ScalarPointPair[T]{
		{*new(curve25519.Scalar).One(), sal.R_P},
		{e, *new(curve25519.PublicKey[T]).Subtract(new(curve25519.PublicKey[T]).Subtract(&sal.P, &input.OTilde), &input.R)},

		// RHS
		{*new(curve25519.Scalar).Negate(&sal.SZ), *curve25519.FromPoint[T](crypto.GeneratorU.Point)},
		{*new(curve25519.Scalar).Negate(&sal.SR_P), *curve25519.FromPoint[T](crypto.GeneratorT.Point)},
	}, randomReader)

	// L GSP Verification Statement
	verifier.Queue(struct{}{}, []multiexp.ScalarPointPair[T]{
		{*new(curve25519.Scalar).One(), sal.R_L},
		{e, *L},

		// RHS
		{*new(curve25519.Scalar).Negate(&sal.SAlpha), input.ITilde},
		// This term was supposed to be subtracted, so our negation cancels out
		{sal.SZ, *curve25519.FromPoint[T](crypto.GeneratorU.Point)},
	}, randomReader)
}

func (sal *SpendAuthAndLinkability[T]) FromReader(reader utils.ReaderAndByteReader) (err error) {
	if err = sal.P.FromReader(reader); err != nil {
		return err
	}
	if err = sal.A.FromReader(reader); err != nil {
		return err
	}
	if err = sal.B.FromReader(reader); err != nil {
		return err
	}
	if err = sal.R_O.FromReader(reader); err != nil {
		return err
	}
	if err = sal.R_P.FromReader(reader); err != nil {
		return err
	}
	if err = sal.R_L.FromReader(reader); err != nil {
		return err
	}

	var sec curve25519.PrivateKeyBytes
	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = sal.SAlpha.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = sal.SBeta.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = sal.SDelta.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = sal.SY.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = sal.SZ.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = sal.SR_P.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}
	return nil
}
