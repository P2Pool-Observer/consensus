package curve25519

import (
	"crypto/rand"
	"encoding/binary"
	"math/bits"
	"testing"
)

func TestBytesToScalar32(t *testing.T) {
	var scalarBytes [64]byte
	_, _ = rand.Read(scalarBytes[:PrivateKeySize])
	// force high value
	scalarBytes[31] = 0xff

	expected, err := new(Scalar).SetWideBytes(scalarBytes[:])
	if err != nil {
		t.Fatal(err)
	}

	{
		var sc Scalar
		BytesToScalar32(&sc, [32]byte(scalarBytes[:PrivateKeySize]))
		if sc.Equal(expected) == 0 {
			t.Fatalf("expected %x got %x", expected.Bytes(), sc.Bytes())
		}
	}
}

func TestScalarIsReduced32(t *testing.T) {
	testScalarLess(t, order)
}

func TestScalarIsLimit32(t *testing.T) {
	testScalarLess(t, limit)
}

func testScalarLess[T ~[PrivateKeySize]byte](t *testing.T, limit T) {
	var minusOne, plusOne T

	dec := func(a T) (out T) {
		s1, borrow := bits.Sub64(binary.LittleEndian.Uint64(a[:]), 1, 0)
		s2, borrow := bits.Sub64(binary.LittleEndian.Uint64(a[8:]), 0, borrow)
		s3, borrow := bits.Sub64(binary.LittleEndian.Uint64(a[16:]), 0, borrow)
		s4, _ := bits.Sub64(binary.LittleEndian.Uint64(a[24:]), 0, borrow)

		binary.LittleEndian.PutUint64(out[:], s1)
		binary.LittleEndian.PutUint64(out[8:], s2)
		binary.LittleEndian.PutUint64(out[16:], s3)
		binary.LittleEndian.PutUint64(out[24:], s4)
		return out
	}

	inc := func(a T) (out T) {
		s1, carry := bits.Add64(binary.LittleEndian.Uint64(a[:]), 1, 0)
		s2, carry := bits.Add64(binary.LittleEndian.Uint64(a[8:]), 0, carry)
		s3, carry := bits.Add64(binary.LittleEndian.Uint64(a[16:]), 0, carry)
		s4, _ := bits.Add64(binary.LittleEndian.Uint64(a[24:]), 0, carry)

		binary.LittleEndian.PutUint64(out[:], s1)
		binary.LittleEndian.PutUint64(out[8:], s2)
		binary.LittleEndian.PutUint64(out[16:], s3)
		binary.LittleEndian.PutUint64(out[24:], s4)
		return out
	}

	minusOne = dec(limit)
	plusOne = inc(limit)

	limbs := scalarLimbs(limit)

	if !scalarLess(minusOne, &limbs) {
		t.Fatal("expected limit-1 < limit")
	}

	if scalarLess(limit, &limbs) {
		t.Fatal("expected limit >= limit")
	}

	if scalarLess(plusOne, &limbs) {
		t.Fatal("expected limit+1 > limit")
	}

	// variable time

	if !scalarLessVarTime(minusOne, limit) {
		t.Fatal("expected limit-1 < limit")
	}

	if scalarLessVarTime(limit, limit) {
		t.Fatal("expected limit >= limit")
	}

	if scalarLessVarTime(plusOne, limit) {
		t.Fatal("expected limit+1 > limit")
	}
}
