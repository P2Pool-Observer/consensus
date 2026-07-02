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

type RerandomizedOutput[T curve25519.PointOperations] struct {
	OTilde curve25519.PublicKey[T]
	ITilde curve25519.PublicKey[T]
	R      curve25519.PublicKey[T]
	CTilde curve25519.PublicKey[T]

	R_O   curve25519.Scalar
	R_I   curve25519.Scalar
	R_R_I curve25519.Scalar
	R_C   curve25519.Scalar
}

func (output *RerandomizedOutput[T]) Input() *Input[T] {
	return &Input[T]{
		OTilde: output.OTilde,
		ITilde: output.ITilde,
		R:      output.R,
		CTilde: output.CTilde,
	}
}

func RerandomizeOutput[T curve25519.PointOperations](O, I, C *curve25519.PublicKey[T], randomReader io.Reader) (output RerandomizedOutput[T]) {
	curve25519.RandomScalar(&output.R_O, randomReader)
	curve25519.RandomScalar(&output.R_I, randomReader)
	curve25519.RandomScalar(&output.R_R_I, randomReader)
	curve25519.RandomScalar(&output.R_C, randomReader)

	output.OTilde.Add(O, new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&output.R_O, crypto.GeneratorT))
	output.ITilde.Add(I, new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&output.R_I, crypto.GeneratorU))
	output.R.Add(
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&output.R_I, crypto.GeneratorV),
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&output.R_R_I, crypto.GeneratorT),
	)
	output.CTilde.Add(C, new(curve25519.PublicKey[T]).ScalarBaseMult(&output.R_C))

	return output
}

type OpenedInput[T curve25519.PointOperations] struct {
	OTilde curve25519.PublicKey[T]
	ITilde curve25519.PublicKey[T]
	R      curve25519.PublicKey[T]
	CTilde curve25519.PublicKey[T]

	// O~ = xG + yT
	X curve25519.Scalar
	Y curve25519.Scalar

	// R = r_i V + r_r_i T
	R_I   curve25519.Scalar
	R_R_I curve25519.Scalar
}

func OpenInput[T curve25519.PointOperations](rerandomizedOutput *RerandomizedOutput[T], x, y *curve25519.Scalar) *OpenedInput[T] {
	yTilde := new(curve25519.Scalar).Add(&rerandomizedOutput.R_O, y)
	if new(curve25519.PublicKey[T]).Add(
		new(curve25519.PublicKey[T]).ScalarBaseMult(x),
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(yTilde, crypto.GeneratorT),
	).Equal(&rerandomizedOutput.OTilde) == 0 {
		return nil
	}

	return &OpenedInput[T]{
		OTilde: rerandomizedOutput.OTilde,
		ITilde: rerandomizedOutput.ITilde,
		R:      rerandomizedOutput.R,
		CTilde: rerandomizedOutput.CTilde,

		X:     *x,
		Y:     *yTilde,
		R_I:   rerandomizedOutput.R_I,
		R_R_I: rerandomizedOutput.R_R_I,
	}
}

func (opening *OpenedInput[T]) Input() *Input[T] {
	return &Input[T]{
		OTilde: opening.OTilde,
		ITilde: opening.ITilde,
		R:      opening.R,
		CTilde: opening.CTilde,
	}
}

func (opening *OpenedInput[T]) Prove(signableTxHash types.Hash, randomReader io.Reader) (L curve25519.PublicKey[T], sal SpendAuthAndLinkability[T]) {
	L.Subtract(
		new(curve25519.PublicKey[T]).ScalarMult(&opening.X, &opening.ITilde),
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(
			new(curve25519.Scalar).Multiply(&opening.R_I, &opening.X),
			crypto.GeneratorU,
		),
	)

	var alpha, beta, delta, mu, r_y, r_z, r_p, r_r_p, x_r_i curve25519.Scalar
	curve25519.RandomScalar(&alpha, randomReader)
	curve25519.RandomScalar(&beta, randomReader)
	curve25519.RandomScalar(&delta, randomReader)
	curve25519.RandomScalar(&mu, randomReader)
	curve25519.RandomScalar(&r_y, randomReader)
	curve25519.RandomScalar(&r_z, randomReader)
	curve25519.RandomScalar(&r_p, randomReader)
	curve25519.RandomScalar(&r_r_p, randomReader)

	x_r_i.Multiply(&opening.X, &opening.R_I)

	sal.P.Add(new(curve25519.PublicKey[T]).ScalarBaseMult(&opening.X), new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&opening.R_I, crypto.GeneratorV))
	sal.P.Add(&sal.P, new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&x_r_i, crypto.GeneratorU))
	sal.P.Add(&sal.P, new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&r_p, crypto.GeneratorT))

	var alpha_G curve25519.PublicKey[T]
	alpha_G.ScalarBaseMult(&alpha)

	sal.A.Add(&alpha_G, new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&beta, crypto.GeneratorV))
	sal.A.Add(&sal.A,
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(
			new(curve25519.Scalar).Add(
				new(curve25519.Scalar).Multiply(&alpha, &opening.R_I),
				new(curve25519.Scalar).Multiply(&beta, &opening.X),
			),
			crypto.GeneratorU,
		),
	)
	sal.A.Add(&sal.A, new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&delta, crypto.GeneratorT))

	sal.B.Add(
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(new(curve25519.Scalar).Multiply(&alpha, &beta), crypto.GeneratorU),
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&mu, crypto.GeneratorT),
	)

	sal.R_O.Add(&alpha_G, new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&r_y, crypto.GeneratorT))
	sal.R_P.Add(
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&r_z, crypto.GeneratorU),
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&r_r_p, crypto.GeneratorT),
	)
	sal.R_L.Subtract(
		new(curve25519.PublicKey[T]).ScalarMult(&alpha, &opening.ITilde),
		new(curve25519.PublicKey[T]).ScalarMultPrecomputed(&r_z, crypto.GeneratorU),
	)

	var e, r_p_double_quote curve25519.Scalar
	sal.Challenge(&e, signableTxHash, opening.Input(), &L)

	sal.SAlpha.Add(&alpha, new(curve25519.Scalar).Multiply(&e, &opening.X))
	sal.SBeta.Add(&beta, new(curve25519.Scalar).Multiply(&e, &opening.R_I))

	sal.SDelta.Add(&mu, new(curve25519.Scalar).Multiply(&e, &delta))
	sal.SDelta.Add(&sal.SDelta, new(curve25519.Scalar).Multiply(&r_p, new(curve25519.Scalar).Multiply(&e, &e)))

	sal.SY.Add(&r_y, new(curve25519.Scalar).Multiply(&e, &opening.Y))
	// z is x_r_i
	sal.SZ.Add(&r_z, new(curve25519.Scalar).Multiply(&e, &x_r_i))

	// r_p is overloaded into r_p' and r_p'' by the paper, hence this distinguishing
	r_p_double_quote.Subtract(&r_p, &opening.Y)
	r_p_double_quote.Subtract(&r_p_double_quote, &opening.R_R_I)

	sal.SR_P.Add(&r_r_p, new(curve25519.Scalar).Multiply(&e, &r_p_double_quote))

	return L, sal
}

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

type BatchVerifier[T curve25519.PointOperations] = multiexp.BatchVerifier[struct{}, curve25519.PublicKey[T], curve25519.Scalar, *curve25519.PublicKey[T], *curve25519.Scalar]
type ScalarPointPair[T curve25519.PointOperations] = multiexp.ScalarPointPair[curve25519.PublicKey[T], curve25519.Scalar, *curve25519.PublicKey[T], *curve25519.Scalar]

func (sal *SpendAuthAndLinkability[T]) Verify(verifier *BatchVerifier[T], signableTxHash types.Hash, input *Input[T], L *curve25519.PublicKey[T], randomReader io.Reader) {

	var e curve25519.Scalar
	sal.Challenge(&e, signableTxHash, input, L)

	// BP+ Verification Statement
	verifier.Queue(struct{}{}, []ScalarPointPair[T]{
		{S: *new(curve25519.Scalar).Multiply(&e, &e), P: sal.P},
		{S: e, P: sal.A},
		{S: *new(curve25519.Scalar).One(), P: sal.B},

		// RHS
		{S: *new(curve25519.Scalar).Negate(new(curve25519.Scalar).Multiply(&sal.SAlpha, &e)), P: *curve25519.FromPoint[T](crypto.GeneratorG.Point)},
		{S: *new(curve25519.Scalar).Negate(new(curve25519.Scalar).Multiply(&sal.SBeta, &e)), P: *curve25519.FromPoint[T](crypto.GeneratorV.Point)},
		{S: *new(curve25519.Scalar).Negate(new(curve25519.Scalar).Multiply(&sal.SAlpha, &sal.SBeta)), P: *curve25519.FromPoint[T](crypto.GeneratorU.Point)},
		{S: *new(curve25519.Scalar).Negate(&sal.SDelta), P: *curve25519.FromPoint[T](crypto.GeneratorT.Point)},
	}, randomReader)

	// O_tilde GSP Verification Statement
	verifier.Queue(struct{}{}, []ScalarPointPair[T]{
		{S: *new(curve25519.Scalar).One(), P: sal.R_O},
		{S: e, P: input.OTilde},

		// RHS
		{S: *new(curve25519.Scalar).Negate(&sal.SAlpha), P: *curve25519.FromPoint[T](crypto.GeneratorG.Point)},
		{S: *new(curve25519.Scalar).Negate(&sal.SY), P: *curve25519.FromPoint[T](crypto.GeneratorT.Point)},
	}, randomReader)

	// P' GSP Verification Statement
	verifier.Queue(struct{}{}, []ScalarPointPair[T]{
		{S: *new(curve25519.Scalar).One(), P: sal.R_P},
		{S: e, P: *new(curve25519.PublicKey[T]).Subtract(new(curve25519.PublicKey[T]).Subtract(&sal.P, &input.OTilde), &input.R)},

		// RHS
		{S: *new(curve25519.Scalar).Negate(&sal.SZ), P: *curve25519.FromPoint[T](crypto.GeneratorU.Point)},
		{S: *new(curve25519.Scalar).Negate(&sal.SR_P), P: *curve25519.FromPoint[T](crypto.GeneratorT.Point)},
	}, randomReader)

	// L GSP Verification Statement
	verifier.Queue(struct{}{}, []ScalarPointPair[T]{
		{S: *new(curve25519.Scalar).One(), P: sal.R_L},
		{S: e, P: *L},

		// RHS
		{S: *new(curve25519.Scalar).Negate(&sal.SAlpha), P: input.ITilde},
		// This term was supposed to be subtracted, so our negation cancels out
		{S: sal.SZ, P: *curve25519.FromPoint[T](crypto.GeneratorU.Point)},
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
