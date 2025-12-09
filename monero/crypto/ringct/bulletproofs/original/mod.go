package original

import (
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type AggregateRangeProof[T curve25519.PointOperations] struct {
	A    curve25519.PublicKey[T]
	S    curve25519.PublicKey[T]
	T1   curve25519.PublicKey[T]
	T2   curve25519.PublicKey[T]
	TauX curve25519.Scalar
	Mu   curve25519.Scalar
	IP   InnerProductProof[T]
	THat curve25519.Scalar
}

func (arp *AggregateRangeProof[T]) Verify(commitments []curve25519.PublicKey[T], randomReader io.Reader) bool {
	var verifier BatchVerifier[T]
	statement := AggregateRangeStatement[T]{
		Commitments: commitments,
	}
	if !statement.Verify(&verifier, arp, randomReader) {
		return false
	}
	return verifier.Verify()
}

func (arp *AggregateRangeProof[T]) BufferLength(signature bool) int {
	return curve25519.PublicKeySize*4 + curve25519.PrivateKeySize*3 + arp.IP.BufferLength(signature)
}

func (arp *AggregateRangeProof[T]) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	buf := preAllocatedBuf
	buf, _ = arp.A.AppendBinary(buf)
	buf, _ = arp.S.AppendBinary(buf)
	buf, _ = arp.T1.AppendBinary(buf)
	buf, _ = arp.T2.AppendBinary(buf)
	buf = append(buf, arp.TauX.Bytes()...)
	buf = append(buf, arp.Mu.Bytes()...)
	if !signature {
		buf = binary.AppendUvarint(buf, uint64(len(arp.IP.L)))
	}
	for _, e := range arp.IP.L {
		buf, _ = e.AppendBinary(buf)
	}
	if !signature {
		buf = binary.AppendUvarint(buf, uint64(len(arp.IP.R)))
	}
	for _, e := range arp.IP.R {
		buf, _ = e.AppendBinary(buf)
	}
	buf = append(buf, arp.IP.A.Bytes()...)
	buf = append(buf, arp.IP.B.Bytes()...)

	buf = append(buf, arp.THat.Bytes()...)

	return buf, nil
}

func (arp *AggregateRangeProof[T]) FromReader(reader utils.ReaderAndByteReader) (err error) {

	if err = arp.A.FromReader(reader); err != nil {
		return err
	}
	if err = arp.S.FromReader(reader); err != nil {
		return err
	}
	if err = arp.T1.FromReader(reader); err != nil {
		return err
	}
	if err = arp.T2.FromReader(reader); err != nil {
		return err
	}

	var sec curve25519.PrivateKeyBytes
	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.TauX.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.Mu.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	var n uint64
	{
		if n, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		var p curve25519.PublicKey[T]
		for range n {
			if err = p.FromReader(reader); err != nil {
				return err
			}
			arp.IP.L = append(arp.IP.L, p)
		}
	}
	{
		if n, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		var p curve25519.PublicKey[T]
		for range n {
			if err = p.FromReader(reader); err != nil {
				return err
			}
			arp.IP.R = append(arp.IP.R, p)
		}
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.IP.A.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.IP.B.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.THat.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	return nil
}

type AggregateRangeStatement[T curve25519.PointOperations] struct {
	Commitments []curve25519.PublicKey[T]
}

var eight = (&curve25519.PrivateKeyBytes{8}).Scalar()
var invEight = new(curve25519.Scalar).Invert(eight)

func (ags AggregateRangeStatement[T]) InitialTranscript() (S curve25519.Scalar, V []curve25519.PublicKey[T]) {
	V = slices.Clone(ags.Commitments)
	buf := make([]byte, 0, len(V)*curve25519.PublicKeySize)
	for i := range V {
		V[i].ScalarMult(invEight, &V[i])
		buf = append(buf, V[i].Bytes()...)
	}
	crypto.ScalarDeriveLegacy(&S, buf)
	return S, V
}

func (ags AggregateRangeStatement[T]) TranscriptAS(transcript curve25519.Scalar, A, S *curve25519.PublicKey[T]) (y, z curve25519.Scalar) {
	crypto.ScalarDeriveLegacy(&y, transcript.Bytes(), A.Bytes(), S.Bytes())
	crypto.ScalarDeriveLegacy(&z, y.Bytes())
	return y, z
}

func (ags AggregateRangeStatement[T]) TranscriptT12(transcript curve25519.Scalar, T1, T2 *curve25519.PublicKey[T]) (t12 curve25519.Scalar) {
	tBytes := transcript.Bytes()
	crypto.ScalarDeriveLegacy(&t12, tBytes, tBytes, T1.Bytes(), T2.Bytes())
	return t12
}

func (ags AggregateRangeStatement[T]) TranscriptTauXMuTHat(transcript curve25519.Scalar, TauX, Mu, THat *curve25519.Scalar) (t curve25519.Scalar) {
	tBytes := transcript.Bytes()
	crypto.ScalarDeriveLegacy(&t, tBytes, tBytes, TauX.Bytes(), Mu.Bytes(), THat.Bytes())
	return t
}

var scalarOne = (&curve25519.PrivateKeyBytes{1}).Scalar()

var generatorHInvEight = new(curve25519.Point).ScalarMult(invEight, crypto.GeneratorH.Point)
var generatorGInvEight = new(curve25519.Point).ScalarMult(invEight, crypto.GeneratorG.Point)

func (ags AggregateRangeStatement[T]) Prove(witness AggregateRangeWitness[T], randomReader io.Reader) (proof AggregateRangeProof[T], err error) {
	//TODO: recover
	if len(ags.Commitments) != len(witness.Commitments) {
		return AggregateRangeProof[T]{}, errors.New("commitments mismatch")
	}
	var committed curve25519.PublicKey[T]
	for i := range witness.Commitments {
		ringct.CalculateCommitment[T](&committed, witness.Commitments[i])
		if committed.Equal(&ags.Commitments[i]) == 0 {
			return AggregateRangeProof[T]{}, errors.New("commitments mismatch")
		}
	}

	transcript, _ := ags.InitialTranscript()

	// Find out the padded amount of commitments
	paddedPowOf2 := bulletproofs.PaddedPowerOfTwo(len(witness.Commitments))

	var aL bulletproofs.ScalarVector[T]
	for _, commitment := range witness.Commitments {
		aL = append(aL, bulletproofs.Decompose[T](commitment.Amount)...)
	}
	aR := slices.Clone(aL).Subtract(scalarOne)

	var alpha curve25519.Scalar
	curve25519.RandomScalar(&alpha, randomReader)

	var A, S curve25519.PublicKey[T]
	{
		A.Add(aL.MultiplyPoints(new(curve25519.PublicKey[T]), bulletproofs.Generator.G[:len(aL)]), aR.MultiplyPoints(new(curve25519.PublicKey[T]), bulletproofs.Generator.H[:len(aR)]))
		A.Add(&A, new(curve25519.PublicKey[T]).ScalarBaseMult(&alpha))
		A.ScalarMult(invEight, &A)
	}

	sL := make(bulletproofs.ScalarVector[T], paddedPowOf2*bulletproofs.CommitmentBits)
	sR := make(bulletproofs.ScalarVector[T], paddedPowOf2*bulletproofs.CommitmentBits)
	for i := range paddedPowOf2 * bulletproofs.CommitmentBits {
		curve25519.RandomScalar(&sL[i], randomReader)
		curve25519.RandomScalar(&sR[i], randomReader)
	}
	var rho curve25519.Scalar
	curve25519.RandomScalar(&rho, randomReader)
	{
		S.Add(sL.MultiplyPoints(new(curve25519.PublicKey[T]), bulletproofs.Generator.G[:len(sL)]), sR.MultiplyPoints(new(curve25519.PublicKey[T]), bulletproofs.Generator.H[:len(sR)]))
		S.Add(&S, new(curve25519.PublicKey[T]).ScalarBaseMult(&rho))
		S.ScalarMult(invEight, &S)
	}

	var y curve25519.Scalar
	y, transcript = ags.TranscriptAS(transcript, &A, &S)
	z := bulletproofs.AppendScalarVectorPowers[T](make(bulletproofs.ScalarVector[T], 0, 3+paddedPowOf2), &transcript, 3+paddedPowOf2)
	twos := bulletproofs.TwoScalarVectorPowers[T]()

	l0 := slices.Clone(aL).Subtract(&z[1])
	l1 := sL

	yPowN := bulletproofs.AppendScalarVectorPowers[T](make(bulletproofs.ScalarVector[T], 0, len(aR)), &y, len(aR))

	r0 := (slices.Clone(sR).Add(&z[1])).MultiplyVec(yPowN)
	r1 := slices.Clone(sR).MultiplyVec(yPowN)
	{
		for j := range paddedPowOf2 {
			for i := range bulletproofs.CommitmentBits {
				r0[(j*bulletproofs.CommitmentBits)+i].Add(&r0[(j*bulletproofs.CommitmentBits)+i], new(curve25519.Scalar).Multiply(&z[2+j], &twos[i]))
			}
		}
	}

	var t1, t2, tau1, tau2 curve25519.Scalar
	{
		var tmp1, tmp2 curve25519.Scalar
		tmp1 = l0.InnerProduct(r1)
		tmp2 = r0.InnerProduct(l1)
		t1.Add(&tmp1, &tmp2)
		t2 = l1.InnerProduct(r1)
	}
	curve25519.RandomScalar(&tau1, randomReader)
	curve25519.RandomScalar(&tau2, randomReader)

	var T1, T2 curve25519.PublicKey[T]
	T1.DoubleScalarMult(&t1, curve25519.FromPoint[T](generatorHInvEight), &tau1, curve25519.FromPoint[T](generatorGInvEight))
	T2.DoubleScalarMult(&t2, curve25519.FromPoint[T](generatorHInvEight), &tau2, curve25519.FromPoint[T](generatorGInvEight))

	transcript = ags.TranscriptT12(transcript, &T1, &T2)
	x := transcript
	l := l0.AddVec(slices.Clone(l1).Multiply(&x))
	r := r0.AddVec(slices.Clone(r1).Multiply(&x))

	THat := l.InnerProduct(r)
	TauX := new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Add(new(curve25519.Scalar).Multiply(&tau2, &x), &tau1), &x)
	for i, commitment := range witness.Commitments {
		TauX.Add(TauX, new(curve25519.Scalar).Multiply(&z[2+i], &commitment.Mask))
	}
	mu := new(curve25519.Scalar).Add(&alpha, new(curve25519.Scalar).Multiply(&rho, &x))

	yInvPowN := bulletproofs.AppendScalarVectorPowers[T](make(bulletproofs.ScalarVector[T], 0, len(l)), new(curve25519.Scalar).Invert(&y), len(l))

	transcript = ags.TranscriptTauXMuTHat(transcript, TauX, mu, &THat)
	xIp := transcript

	ips := InnerProductStatement[T]{
		HBoldWeights: yInvPowN,
		U:            xIp,
	}
	ip, err := ips.Prove(transcript, NewInnerProductWitness[T](l, r))
	if err != nil {
		return AggregateRangeProof[T]{}, err
	}

	proof = AggregateRangeProof[T]{
		A:    A,
		S:    S,
		T1:   T1,
		TauX: *TauX,
		Mu:   *mu,
		THat: THat,
		IP:   ip,
	}

	{
		// debug checks
		var verifier BatchVerifier[T]
		if !ags.Verify(&verifier, &proof, randomReader) {
			return AggregateRangeProof[T]{}, errors.New("failed to verify")
		}
		if !verifier.Verify() {
			return AggregateRangeProof[T]{}, errors.New("failed to verify")
		}
	}

	return proof, nil
}

func (ags AggregateRangeStatement[T]) Verify(verifier *BatchVerifier[T], proof *AggregateRangeProof[T], randomReader io.Reader) bool {
	// Find out the padded amount of commitments
	paddedPowOf2 := bulletproofs.PaddedPowerOfTwo(len(ags.Commitments))

	ipRows := paddedPowOf2 * bulletproofs.CommitmentBits

	for len(verifier.GBold) < ipRows {
		verifier.GBold = append(verifier.GBold, curve25519.Scalar{})
		verifier.HBold = append(verifier.HBold, curve25519.Scalar{})
	}

	transcript, commitments := ags.InitialTranscript()
	for i := range commitments {
		commitments[i].MultByCofactor(&commitments[i])
	}

	y, transcript := ags.TranscriptAS(transcript, &proof.A, &proof.S)
	z := bulletproofs.AppendScalarVectorPowers[T](nil, &transcript, 3+paddedPowOf2)
	transcript = ags.TranscriptT12(transcript, &proof.T1, &proof.T2)
	x := transcript
	transcript = ags.TranscriptTauXMuTHat(transcript, &proof.TauX, &proof.Mu, &proof.THat)

	xIp := transcript

	var A, S, T1, T2 curve25519.PublicKey[T]
	A.MultByCofactor(&proof.A)
	S.MultByCofactor(&proof.S)
	T1.MultByCofactor(&proof.T1)
	T2.MultByCofactor(&proof.T2)

	yPowN := bulletproofs.AppendScalarVectorPowers[T](nil, &y, ipRows)
	yInvPowN := bulletproofs.AppendScalarVectorPowers[T](nil, new(curve25519.Scalar).Invert(&y), ipRows)

	twos := bulletproofs.TwoScalarVectorPowers[T]()

	// 65
	{
		var weight curve25519.Scalar
		curve25519.RandomScalar(&weight, randomReader)
		verifier.H.Add(&verifier.H, new(curve25519.Scalar).Multiply(&weight, &proof.THat))
		verifier.G.Add(&verifier.G, new(curve25519.Scalar).Multiply(&weight, &proof.TauX))

		// Now that we've accumulated the lhs, negate the weight and accumulate the rhs
		// These will now sum to 0 if equal
		weight.Negate(&weight)

		yPowNSum := yPowN.Sum()
		verifier.H.Add(&verifier.H, new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&weight, new(curve25519.Scalar).Subtract(&z[1], &z[2])), &yPowNSum))

		for i, commitment := range commitments {
			verifier.Other = append(verifier.Other, bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(&weight, &z[2+i]), P: commitment})
		}

		twosSum := twos.Sum()
		for i := range paddedPowOf2 {
			verifier.H.Subtract(&verifier.H, new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&weight, &z[3+i]), &twosSum))
		}

		verifier.Other = append(verifier.Other,
			bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(&weight, &x), P: T1},
			bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(&weight, new(curve25519.Scalar).Multiply(&x, &x)), P: T2},
		)
	}

	var ipWeight curve25519.Scalar
	curve25519.RandomScalar(&ipWeight, randomReader)

	// 66
	verifier.Other = append(verifier.Other,
		bulletproofs.ScalarPointPair[T]{S: ipWeight, P: A},
		bulletproofs.ScalarPointPair[T]{S: *new(curve25519.Scalar).Multiply(&ipWeight, &x), P: S},
	)

	// We can replace these with a g_sum, h_sum scalar in the batch verifier
	// It'd trade `2 * ip_rows` scalar additions (per proof) for one scalar addition and an
	// additional term in the MSM
	ipZ := new(curve25519.Scalar).Multiply(&ipWeight, &z[1])
	for i := range ipRows {
		verifier.HBold[i].Add(&verifier.HBold[i], ipZ)
	}
	negIpZ := new(curve25519.Scalar).Negate(ipZ)
	for i := range ipRows {
		verifier.GBold[i].Add(&verifier.GBold[i], negIpZ)
	}
	for j := range paddedPowOf2 {
		for i := range bulletproofs.CommitmentBits {
			fullI := (j * bulletproofs.CommitmentBits) + i

			verifier.HBold[fullI].Add(&verifier.HBold[fullI], new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&ipWeight, &yInvPowN[fullI]), new(curve25519.Scalar).Multiply(&z[2+j], &twos[i])))
		}
	}
	verifier.H.Add(&verifier.H, new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&ipWeight, &xIp), &proof.THat))

	// 67, 68
	verifier.G.Add(&verifier.G, new(curve25519.Scalar).Multiply(&ipWeight, new(curve25519.Scalar).Negate(&proof.Mu)))

	return (&InnerProductStatement[T]{
		HBoldWeights: yInvPowN,
		U:            xIp,
	}).Verify(verifier, ipRows, transcript, ipWeight, proof.IP) == nil
}

type AggregateRangeWitness[T curve25519.PointOperations] struct {
	Commitments []ringct.LazyCommitment
}
