package plus

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
	"git.gammaspectra.live/P2Pool/edwards25519"
)

var eight = (&curve25519.PrivateKeyBytes{8}).Scalar()
var one = (&curve25519.PrivateKeyBytes{1}).Scalar()
var two = (&curve25519.PrivateKeyBytes{2}).Scalar()
var invEight = new(curve25519.Scalar).Invert(eight)

type AggregateRangeStatement[T curve25519.PointOperations] struct {
	V []curve25519.PublicKey[T]
}

func (ars AggregateRangeStatement[T]) TranscriptA(transcript *curve25519.Scalar, A *curve25519.PublicKey[T]) (y, z curve25519.Scalar) {
	crypto.ScalarDeriveLegacy(&y, transcript.Bytes(), A.Bytes())
	crypto.ScalarDeriveLegacy(&z, y.Bytes())
	*transcript = z
	return y, z
}

func (ars AggregateRangeStatement[T]) DJ(j, m int) bulletproofs.ScalarVector[T] {
	dj := make(bulletproofs.ScalarVector[T], 0, m*bulletproofs.CommitmentBits)
	for range (j - 1) * bulletproofs.CommitmentBits {
		dj = append(dj, curve25519.Scalar{})
	}
	dj = append(dj, bulletproofs.NewScalarVectorPowers[T](two, bulletproofs.CommitmentBits)...)
	for range (m - j) * bulletproofs.CommitmentBits {
		dj = append(dj, curve25519.Scalar{})
	}
	return dj
}

func (ars AggregateRangeStatement[T]) ComputeAHat(V []curve25519.PublicKey[T], transcript *curve25519.Scalar, A *curve25519.PublicKey[T]) (ahc AggregateHatComputation[T]) {
	y, z := ars.TranscriptA(transcript, A)

	A = new(curve25519.PublicKey[T]).MultByCofactor(A)

	for len(V) < bulletproofs.PaddedPowerOfTwo(len(V)) {
		V = append(V, *curve25519.FromPoint[T](edwards25519.NewIdentityPoint()))
	}

	mn := len(V) * bulletproofs.CommitmentBits

	// 2, 4, 6, 8... powers of z, of length equivalent to the amount of commitments
	zPow := make(bulletproofs.ScalarVector[T], 0, mn)

	// z**2
	zPow = append(zPow, *new(curve25519.Scalar).Multiply(&z, &z))

	d := make(bulletproofs.ScalarVector[T], mn)

	for j := 1; j <= len(V); j++ {
		zPow = append(zPow, *new(curve25519.Scalar).Multiply(&zPow[len(zPow)-1], &zPow[0]))
		d.AddVec(ars.DJ(j, len(V)).Multiply(&zPow[j-1]))
	}

	ascendingY := make(bulletproofs.ScalarVector[T], 0, len(d))
	ascendingY = append(ascendingY, y)
	for i := 1; i < len(d); i++ {
		ascendingY = append(ascendingY, *new(curve25519.Scalar).Multiply(&ascendingY[i-1], &y))
	}

	yPows := ascendingY.Sum()

	descendingY := slices.Clone(ascendingY)
	slices.Reverse(descendingY)

	dDescendingY := slices.Clone(d).MultiplyVec(descendingY)
	dDescendingYPlusZ := dDescendingY.Add(&z)

	yMnPlusOne := new(curve25519.Scalar).Multiply(&descendingY[0], &y)

	commitmentAccum := curve25519.FromPoint[T](edwards25519.NewIdentityPoint())
	for j, commitment := range V {
		commitmentAccum.Add(commitmentAccum, new(curve25519.PublicKey[T]).ScalarMult(&zPow[j], &commitment))
	}

	negZ := new(curve25519.Scalar).Negate(&z)

	scalars := make([]*curve25519.Scalar, 0, len(dDescendingYPlusZ)*2+2)
	points := make([]*curve25519.PublicKey[T], 0, len(dDescendingYPlusZ)*2+2)

	for i := range dDescendingYPlusZ {
		scalars = append(scalars, negZ)
		points = append(points, curve25519.FromPoint[T](bulletproofs.GeneratorPlus.G[i]))
		scalars = append(scalars, &dDescendingYPlusZ[i])
		points = append(points, curve25519.FromPoint[T](bulletproofs.GeneratorPlus.H[i]))
	}

	scalars = append(scalars, yMnPlusOne)
	points = append(points, commitmentAccum)

	dSum := d.Sum()

	scalars = append(scalars, new(curve25519.Scalar).Subtract(
		new(curve25519.Scalar).Subtract(
			new(curve25519.Scalar).Multiply(&yPows, &z),
			new(curve25519.Scalar).Multiply(&dSum, new(curve25519.Scalar).Multiply(yMnPlusOne, &z)),
		),
		new(curve25519.Scalar).Multiply(&yPows, &zPow[0]),
	))
	points = append(points, curve25519.FromPoint[T](crypto.GeneratorH.Point))

	A.Add(A, new(curve25519.PublicKey[T]).MultiScalarMult(scalars, points))

	return AggregateHatComputation[T]{
		Y:                 y,
		DDescendingYPlusZ: dDescendingYPlusZ,
		YMnPlusOne:        *yMnPlusOne,
		Z:                 z,
		ZPow:              zPow,
		AHat:              *A,
	}
}

func (ars AggregateRangeStatement[T]) Prove(witness AggregateRangeWitness, randomReader io.Reader) (proof AggregateRangeProof[T], err error) {
	if len(ars.V) != len(witness) {
		return AggregateRangeProof[T]{}, errors.New("mismatched length")
	}

	for i, commitment := range ars.V {
		if ringct.CalculateCommitment(new(curve25519.PublicKey[T]), witness[i]).Equal(&commitment) == 0 {
			return AggregateRangeProof[T]{}, errors.New("mismatched commitment")
		}
	}

	// Monero expects all of these points to be torsion-free
	// Generally, for Bulletproofs, it sends points * INV_EIGHT and then performs a torsion clear
	// by multiplying by 8
	// This also restores the original value due to the preprocessing
	// Commitments aren't transmitted INV_EIGHT though, so this multiplies by INV_EIGHT to enable
	// clearing its cofactor without mutating the value
	// For some reason, these values are transcripted * INV_EIGHT, not as transmitted
	V := slices.Clone(ars.V)
	for i := range V {
		V[i].ScalarMult(invEight, &V[i])
	}
	var transcript curve25519.Scalar
	InitialTranscript(&transcript, V)
	for i := range V {
		V[i].MultByCofactor(&V[i])
	}

	// Pad V
	for len(V) < bulletproofs.PaddedPowerOfTwo(len(V)) {
		V = append(V, *curve25519.FromPoint[T](edwards25519.NewIdentityPoint()))
	}

	dJS := make([]bulletproofs.ScalarVector[T], 0, len(V))
	aL := make(bulletproofs.ScalarVector[T], 0, len(V)*bulletproofs.CommitmentBits)

	for j := 1; j <= len(V); j++ {
		dJS = append(dJS, ars.DJ(j, len(V)))
		if len(witness) > j-1 {
			aL = append(aL, bulletproofs.Decompose[T](witness[j-1].Amount)...)
		} else {
			aL = append(aL, bulletproofs.Decompose[T](0)...)
		}
	}

	aR := slices.Clone(aL).Subtract(one)

	var alpha curve25519.Scalar
	curve25519.RandomScalar(&alpha, randomReader)

	scalars := make([]*curve25519.Scalar, 0, len(V)*bulletproofs.CommitmentBits+1)
	points := make([]*curve25519.PublicKey[T], 0, len(V)*bulletproofs.CommitmentBits+1)

	for i := range aL {
		scalars = append(scalars, &aL[i])
		points = append(points, curve25519.FromPoint[T](bulletproofs.GeneratorPlus.G[i]))
	}
	for i := range aR {
		scalars = append(scalars, &aR[i])
		points = append(points, curve25519.FromPoint[T](bulletproofs.GeneratorPlus.H[i]))
	}

	scalars = append(scalars, &alpha)
	points = append(points, curve25519.FromPoint[T](crypto.GeneratorG.Point))

	A := new(curve25519.PublicKey[T]).MultiScalarMult(scalars, points)

	// Multiply by INV_EIGHT per earlier commentary
	A.ScalarMult(invEight, A)

	ahc := ars.ComputeAHat(V, &transcript, A)

	aL.Subtract(&ahc.Z)
	aR.AddVec(ahc.DDescendingYPlusZ)

	for j := 1; j <= len(witness); j++ {
		alpha.Add(&alpha, new(curve25519.Scalar).Multiply(new(curve25519.Scalar).Multiply(&ahc.ZPow[j-1], &witness[j-1].Mask), &ahc.YMnPlusOne))
	}

	wip, err := NewWeightedInnerProductStatement(&ahc.AHat, &ahc.Y, len(V)*bulletproofs.CommitmentBits).Prove(&transcript, WeightedInnerProductWitness[T]{
		A:     aL,
		B:     aR,
		Alpha: alpha,
	}, randomReader)
	if err != nil {
		return AggregateRangeProof[T]{}, err
	}

	return AggregateRangeProof[T]{
		A:   *A,
		WIP: wip,
	}, nil
}

func (arp *AggregateRangeProof[T]) Verify(commitments []curve25519.PublicKey[T], randomReader io.Reader) bool {
	var verifier BatchVerifier[T]
	statement := AggregateRangeStatement[T]{
		V: commitments,
	}
	if !statement.Verify(&verifier, arp, randomReader) {
		return false
	}
	return verifier.Verify()
}

func (ars AggregateRangeStatement[T]) Verify(verifier *BatchVerifier[T], proof *AggregateRangeProof[T], randomReader io.Reader) bool {

	V := slices.Clone(ars.V)
	for i := range V {
		V[i].ScalarMult(invEight, &V[i])
	}
	var transcript curve25519.Scalar
	InitialTranscript(&transcript, V)
	for i := range V {
		V[i].MultByCofactor(&V[i])
	}

	ahc := ars.ComputeAHat(V, &transcript, &proof.A)

	return NewWeightedInnerProductStatement(&ahc.AHat, &ahc.Y, bulletproofs.PaddedPowerOfTwo(len(V)*bulletproofs.CommitmentBits)).Verify(verifier, &transcript, proof.WIP, randomReader)
}

type AggregateRangeWitness []ringct.Commitment

type AggregateRangeProof[T curve25519.PointOperations] struct {
	A   curve25519.PublicKey[T]
	WIP WeightedInnerProductProof[T]
}

func (arp *AggregateRangeProof[T]) BufferLength(signature bool) int {
	return curve25519.PublicKeySize + arp.WIP.BufferLength(signature)
}

func (arp *AggregateRangeProof[T]) AppendBinary(preAllocatedBuf []byte, signature bool) (data []byte, err error) {
	buf := preAllocatedBuf
	buf, _ = arp.A.AppendBinary(buf)
	buf, _ = arp.WIP.A.AppendBinary(buf)
	buf, _ = arp.WIP.B.AppendBinary(buf)
	buf = append(buf, arp.WIP.RAnswer.Bytes()...)
	buf = append(buf, arp.WIP.SAnswer.Bytes()...)
	buf = append(buf, arp.WIP.DeltaAnswer.Bytes()...)
	if !signature {
		buf = binary.AppendUvarint(buf, uint64(len(arp.WIP.L)))
	}
	for _, e := range arp.WIP.L {
		buf, _ = e.AppendBinary(buf)
	}
	if !signature {
		buf = binary.AppendUvarint(buf, uint64(len(arp.WIP.R)))
	}
	for _, e := range arp.WIP.R {
		buf, _ = e.AppendBinary(buf)
	}

	return buf, nil
}

func (arp *AggregateRangeProof[T]) FromReader(reader utils.ReaderAndByteReader) (err error) {

	if err = arp.A.FromReader(reader); err != nil {
		return err
	}
	if err = arp.WIP.A.FromReader(reader); err != nil {
		return err
	}
	if err = arp.WIP.B.FromReader(reader); err != nil {
		return err
	}

	var sec curve25519.PrivateKeyBytes
	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.WIP.RAnswer.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.WIP.SAnswer.SetCanonicalBytes(sec[:]); err != nil {
		return err
	}

	if _, err = utils.ReadFullNoEscape(reader, sec[:]); err != nil {
		return err
	}
	if _, err = arp.WIP.DeltaAnswer.SetCanonicalBytes(sec[:]); err != nil {
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
			arp.WIP.L = append(arp.WIP.L, p)
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
			arp.WIP.R = append(arp.WIP.R, p)
		}
	}

	return nil
}

type AggregateHatComputation[T curve25519.PointOperations] struct {
	Y                 curve25519.Scalar
	DDescendingYPlusZ bulletproofs.ScalarVector[T]
	YMnPlusOne        curve25519.Scalar
	Z                 curve25519.Scalar
	ZPow              bulletproofs.ScalarVector[T]
	AHat              curve25519.PublicKey[T]
}
