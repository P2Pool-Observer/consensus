package divisors

import (
	"crypto/rand"
	"io"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
)

func TestProjective(t *testing.T) {
	t.Run("Edwards25519", func(t *testing.T) {
		testProjective[Edwards25519DivisorCiphersuite](t, rand.Reader)
	})
}

func testProjective[C DivisorCurve[curve.Ciphersuite[P, F], P, F], P any, F any, PE curve.Point[P], FE curve.Field[F]](t *testing.T, randomReader io.Reader) {
	type PP = Projective[C, P, F, FE]
	var c C
	toXY := func(p *P) [2]F {
		x, y, err := c.XY(p)
		if err != nil {
			t.Fatal(err)
		}
		return [2]F{x, y}
	}
	toAffineSlow := func(p *PP) [2]F {
		zInv := FE(new(F)).Invert(&p.Z)
		return [2]F{
			*FE(new(F)).Multiply(&p.X, zInv),
			*FE(new(F)).Multiply(&p.Y, zInv),
		}
	}
	affineAssertEqual := func(a, b [2]F) {
		if FE(&a[0]).Equal(&b[0])&FE(&a[1]).Equal(&b[1]) != 1 {
			t.Fatal()
		}
	}
	projectiveAssertEqual := func(a, b *PP, n string) {
		if a.Equal(b) != 1 {
			t.Fatal(n)
		}
	}

	point := c.Generator()
	projective := new(PP).From(point)
	affineAssertEqual(toAffineSlow(projective), toXY(point))

	doubled := PE(new(P)).Add(point, point)
	doubledProjective := new(PP).Double(projective)
	affineAssertEqual(toAffineSlow(doubledProjective), toXY(doubled))

	triple := PE(new(P)).Add(point, doubled)
	tripleProjective := new(PP).Add(projective, doubledProjective)
	affineAssertEqual(toAffineSlow(tripleProjective), toXY(triple))

	// Handle all possible edge cases within the addition function
	projectiveAssertEqual(new(PP).Add(new(PP).Identity(), new(PP).Identity()), new(PP).Identity(), "identity + identity")
	projectiveAssertEqual(new(PP).Add(new(PP).Identity(), projective), projective, "identity + point")
	projectiveAssertEqual(new(PP).Add(projective, new(PP).Identity()), projective, "point + identity")
	projectiveAssertEqual(new(PP).Add(projective, projective), new(PP).Double(projective), "point + point")
	projectiveAssertEqual(new(PP).Add(projective, new(PP).Negate(projective)), new(PP).Identity(), "point + -point")

	// Handle edge cases with double
	projectiveAssertEqual(new(PP).Double(new(PP).Identity()), new(PP).Identity(), "identity * 2")
}
