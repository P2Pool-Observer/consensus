package plus

import (
	"encoding/binary"
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
var two = (&curve25519.PrivateKeyBytes{2}).Scalar()
var invEight = new(curve25519.Scalar).Invert(eight)

type AggregateRangeStatement[T curve25519.PointOperations] struct {
	GBold []curve25519.PublicKey[T]
	HBold []curve25519.PublicKey[T]

	V []curve25519.PublicKey[T]
}

func (ars AggregateRangeStatement[T]) TranscriptA(transcript *curve25519.Scalar, A *curve25519.PublicKey[T]) (y, z curve25519.Scalar) {
	crypto.ScalarDeriveLegacy(&y, transcript.Bytes(), A.Slice())
	crypto.ScalarDerive(&z, y.Bytes())
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

	d := make(bulletproofs.ScalarVector[T], 0, mn)

	for j := 1; j < len(V); j++ {
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

func (ars AggregateRangeStatement[T]) Verify(verifier *BatchVerifier[T], proof AggregateRangeProof[T], randomReader io.Reader) bool {

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
