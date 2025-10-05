package crypto

import (
	"runtime"
	"sync"

	"git.gammaspectra.live/P2Pool/edwards25519"
)

var pointPool, scalarPool sync.Pool

func init() {
	// separate init, breaks the cycle

	pointPool.New = func() any {
		p := new(edwards25519.Point)
		runtime.SetFinalizer(p, PutEdwards25519Point)
		return p
	}
	scalarPool.New = func() any {
		s := new(edwards25519.Scalar)
		runtime.SetFinalizer(s, PutEdwards25519Scalar)
		return s
	}
}

func GetEdwards25519Point() *edwards25519.Point {
	return pointPool.Get().(*edwards25519.Point)
}

func PutEdwards25519Point(p *edwards25519.Point) {
	pointPool.Put(p)
}

func GetEdwards25519Scalar() *edwards25519.Scalar {
	return scalarPool.Get().(*edwards25519.Scalar)
}

func PutEdwards25519Scalar(s *edwards25519.Scalar) {
	scalarPool.Put(s)
}
