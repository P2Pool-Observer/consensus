package curve

import (
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

// Scalar A full implementation of a Scalar element with helper utilities
type Scalar[S any] interface {
	*S

	BasicField[S]

	// Marshaling

	SetCanonicalBytes(x []byte) (*S, error)
	SetUniformBytes(x []byte) (*S, error)
	Bytes() []byte
}

func RandomScalar[S any, SE Scalar[S]](k *S, r io.Reader) *S {

	var buf [64]byte
	var zeroScalar S
	SE(&zeroScalar).Zero()

	for {
		if _, err := utils.ReadNoEscape(r, buf[:]); err != nil {
			panic(err)
		}

		if _, err := SE(k).SetUniformBytes(buf[:]); err != nil {
			panic(err)
		}

		if SE(k).Equal(&zeroScalar) == 0 {
			return k
		}
	}
}
