package curve25519

import (
	"unsafe"

	"git.gammaspectra.live/P2Pool/edwards25519" //nolint:depguard
)

func BatchBytes[T PointOperations](pubs []*PublicKey[T], out []PublicKeyBytes) {
	// #nosec G103 -- converts to internal Point representation
	points := unsafe.Slice((**Point)(unsafe.Pointer(unsafe.SliceData(pubs))), len(pubs))

	// #nosec G103 -- converts to underlying type
	outPtr := unsafe.Slice((*[PublicKeySize]byte)(unsafe.SliceData(out)), len(out))
	edwards25519.BatchBytes(points, outPtr)
}

func BatchMontgomeryBytes[T PointOperations](pubs []*PublicKey[T], out []MontgomeryPoint) {
	// #nosec G103 -- converts to internal Point representation
	points := unsafe.Slice((**Point)(unsafe.Pointer(unsafe.SliceData(pubs))), len(pubs))

	// #nosec G103 -- converts to underlying type
	outPtr := unsafe.Slice((*[PublicKeySize]byte)(unsafe.SliceData(out)), len(out))
	edwards25519.BatchBytesMontgomery(points, outPtr)
}
